package RefInfo;


import soot.*;
import soot.jimple.infoflow.android.SetupApplication;
import soot.jimple.infoflow.solver.cfg.InfoflowCFG;
import soot.jimple.toolkits.callgraph.Edge;
import soot.options.Options;
import soot.toolkits.graph.DirectedGraph;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

public class RefInfoC {

    /*
    0.
    首先使用flowdroid icfg，确定反射api的位置、pattern

    0.1  根据method的signature确定对应的soot mthod。
            method的signature的获取：可以按照TOSEM2021-Taming Reflection: An Essential Step Toward Whole-program Analysis of Android Apps  //droidra table1，table2 的思路，查java api文档，找到对应method签名后直接获取对应soot method
                considering any call to a method implemented by the four reflection-related classes as a reflective call, except such methods that are overridden from java.lang.Object.
                java.lang.reflect.Field,
                java.lang.reflect.Method,
                java.lang.Class,
                java.lang.reflect.Constructor.
        或者根据这四个class，获取对应soot class包含的所有soot methods，排除掉从java.lang.Object 重写overridden的methods。
    0.2 然后获取apk的icfg。 获取调用、被调用该soot method的调用边。
        fcg中可以获取如下形式的调用信息：
            Edge from specialinvoke r0.<android.app.Activity: void <init>()>() in <de.ecspride.MainActivity: void <init>()> to <android.app.Activity: void <init>()>
        icfg应该可以获取类似的信息。且包含更多的信息，如参数

    1.
    https://github.com/secure-software-engineering/FlowDroid/issues/119  FlowDroid excludes some classes for performance reasons
    flowdroid基于soot，但是据说排除了一些classes。
    后续可以单独用soot来分析apk，对比排除了哪些类。 不过既然排除了，那么这些类就不做污点分析，所以除非在flowdroid补上，否则对污点分析没有帮助；
    ps：flowdroid应该是添加了一些methods（dummy main）和一个dummy main class

    2.
        同时可以和androguard对比，分析的基础是识别了多少classes、methods。
        androguard 分析 ref3-staticArray.apk
        apk总的classes数量 644   #len(dx.get_classes())
        apk总的methods数量 4845 #len(list(dx.get_methods()

        dx.get_classes()，排除external classes（没有实现的类），还有455个classes
    3.
    以及，需要搞清楚flowdroid使用的soot options是什么。 force-android-jar、android-jars？、  Options.src_prec？
        flowdroid参数之一是jar platforms路径。应该是android-jars。 会自动在文件夹中寻找对应android sdk。 找不到时，也能运行。
    4.
    搞清楚soot的options
    force-android-jar（-force-android-jar 可以强制使用某sdk，而不是寻找对应的target sdk）；android-jars（路径是sdk/paltforms。会自动在文件夹中寻找对应android sdk，如platforms/android-21/android.jar）
            采用不同options、不采用android-jar分别有什么作用、影响。
            默认会寻找apk对应的target android sdk version。若找不到会怎样处理？ 若sdk版本不同的影响？
    Options.src_prec采取apk、jimple分别有什么影响？
    以及其他options
    5.
    droidra之前用的sdk版本和分析的apk就不对应。若 (4)分析结果是相关Options对结果影响很大，则需要修改为对应的androidsdk

    ps：
        ref3-staticArray是target android sdk version是android21；  droidbench的target sdk version是android 17
        500apps的target sdk version是多少需要单独看

        FLOWDROID 文档：soot-infoflow-cmd-classes-javadoc.jar
        soot 文档：https://www.sable.mcgill.ca/soot/doc/index.html、https://github.com/soot-oss/soot/wiki...
     */
    public void sootAna(){
        soot.G.reset();

        String apkPath = "D:\\IdeaAndroidProject\\Refinfo\\Apks\\ref3-staticArray.apk";
        String jarsPath = "C:\\Users\\Erio\\AppData\\Local\\Android\\Sdk\\platforms";

        //Options.v().set_src_prec(Options.src_prec_apk_class_jimple);
        Options.v().set_src_prec(Options.src_prec_apk); //

        Options.v().set_process_dir(Collections.singletonList(apkPath));

        Options.v().set_android_jars(jarsPath);
        //Options.v().set_force_android_jar("C:\\Users\\Erio\\AppData\\Local\\Android\\Sdk\\platforms\\android-17\\android.jar");

        Options.v().set_keep_line_number(true);
        Options.v().set_process_multiple_dex(true);


        Options.v().set_wrong_staticness(Options.wrong_staticness_ignore);
        Options.v().set_allow_phantom_refs(true);//设置允许伪类（Phantom class），指的是soot为那些在其classpath找不到的类建立的模型
        Options.v().set_output_format(Options.output_format_dex);//设置soot的输出格式
        Scene.v().loadNecessaryClasses();
        PackManager.v().runPacks();

        //599 = 0 + 144 + 455
        System.out.printf("%d = %d + %d + %d%n",
                Scene.v().getClasses().size(),
                Scene.v().getApplicationClasses().size(),
                Scene.v().getLibraryClasses().size(),
                Scene.v().getPhantomClasses().size()
        );

        /*
        采用不同options和Android sdk 时统计到的class数量：
        Options.v().set_src_prec(Options.src_prec_apk_class_jimple)
            set_force_android_jar
                ANDROID 17：967  set_force_android_jar
        Options.v().set_src_prec(Options.src_prec_apk);
                set_force_android_jar
                    ANDROID 17=1049
                    ANDROID 32=1253
                    ANDROID 18=1052
        */

        return ;
    }

    public static void main(String args[]){
        // Initialize Soot
        SetupApplication analyzer = new SetupApplication("C:\\Users\\Erio\\AppData\\Local\\Android\\Sdk\\platforms",
                "D:\\IdeaAndroidProject\\Refinfo\\Apks\\ref3-staticArray.apk");
        analyzer.constructCallgraph();

        // Iterate over the callgraph
        for (Iterator<Edge> edgeIt = Scene.v().getCallGraph().iterator(); edgeIt.hasNext(); ) {
            Edge edge = edgeIt.next();

            SootMethod smSrc = edge.src();
            Unit uSrc = edge.srcStmt();
            SootMethod smDest = edge.tgt();

            System.out.println("Edge from " + uSrc + " in " + smSrc + " to " + smDest);
        }
        InfoflowCFG icfg = new InfoflowCFG();

        //遍历class。1715 = 12 + 60 + 1643
        System.out.printf("%d = %d + %d + %d%n",
                Scene.v().getClasses().size(),
                Scene.v().getApplicationClasses().size(),
                Scene.v().getLibraryClasses().size(),
                Scene.v().getPhantomClasses().size()
        );

        // 遍历类
        for (SootClass klass : Scene.v().getClasses()) {
            // 类名
            System.out.println(klass.getName());
            // 遍历方法
            for (SootMethod method : klass.getMethods()) {
                // 方法签名
                System.out.println(method.getSignature());
            }
        }



        System.out.println("end");

    }
}
