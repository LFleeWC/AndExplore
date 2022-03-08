package com.beingyi.app.AE.utils;

import android.os.Build;
import android.util.Log;
import android.widget.Toast;

import com.beingyi.app.AE.application.MyApplication;
import com.google.common.collect.Lists;
import com.google.gson.JsonParseException;
import com.google.gson.JsonParser;

import org.apache.commons.lang3.StringUtils;
import org.jf.baksmali.Adaptors.ClassDefinition;
import org.jf.baksmali.BaksmaliOptions;
import org.jf.dexlib2.Opcodes;
import org.jf.dexlib2.dexbacked.DexBackedDexFile;
import org.jf.dexlib2.iface.ClassDef;
import org.jf.dexlib2.writer.builder.DexBuilder;
import org.jf.dexlib2.writer.io.MemoryDataStore;
import org.jf.smali.Smali;
import org.jf.smali.SmaliOptions;
import org.jf.util.IndentingWriter;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.StringWriter;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import dalvik.system.InMemoryDexClassLoader;

/**
 * @ClassName com.beingyi.app.AE.utils
 * @Description
 * @Author xiaoping
 * @Date 2022/03/01
 * @Version 1.0
 */
public class DexStringDecryption {

    byte[] out;

    DexBackedDexFile dex;
    List<String> keeps;
    DexStringEncryptor.EncryptCallBack callBack;
    //    String decodeMethod;
//    String decodeClass;
    InMemoryDexClassLoader inMemoryDexClassLoader;
    DecodeName decodeName;

    public DexStringDecryption(String Input, List<String> keeps, String decodem, InMemoryDexClassLoader inMemoryDexClassLoader, DexStringEncryptor.EncryptCallBack mCallBack) throws Exception {
        File file = new File(Input);
        dex = DexBackedDexFile.fromInputStream(Opcodes.getDefault(), new BufferedInputStream(new FileInputStream(file)));
        this.keeps = keeps;
        this.callBack = mCallBack;
        decodeName = new DecodeName(decodem);
        this.inMemoryDexClassLoader = inMemoryDexClassLoader;
        init();

    }

    public DexStringDecryption(byte[] Input, List<String> keeps, String decodem, InMemoryDexClassLoader inMemoryDexClassLoader, DexStringEncryptor.EncryptCallBack mCallBack) throws Exception {
        dex = DexBackedDexFile.fromInputStream(Opcodes.getDefault(), new ByteArrayInputStream(Input));
        this.keeps = keeps;
        this.callBack = mCallBack;
        // this.decodeMethod=decodem.substring(decodem.split("(\\w+)[^/]\\((.+)\\)(.+)")[0].length());
        // this.decodeClass= decodem.replaceAll("/(\\w+)[^/]\\((.+)\\)(.+)","").replace("/",".")+";".substring(1);
        decodeName = new DecodeName(decodem);
        this.inMemoryDexClassLoader = inMemoryDexClassLoader;
        init();
    }


    public void init() {

        if (keeps == null) {
            keeps = new ArrayList<>();
        }

        keeps.add("LDecoder/");
        keeps.add("Lcom/ae/");
        keeps.add("Ljavax/");
        keeps.add("Lsun1/");
        keeps.add("Lsun/");
        keeps.add("Ljava/");
        keeps.add("Lcom/google/");
        keeps.add("Landroid/");
        keeps.add("Landroidx");

    }

    public void start() throws Exception {

        DexBuilder dexBuilder = new DexBuilder(Opcodes.getDefault());
        dexBuilder.setIgnoreMethodAndFieldError(true);

/*  //解密的文件在自身中
    DexBackedDexFile baseDex = DexBackedDexFile.fromInputStream(Opcodes.getDefault(), new BufferedInputStream(BYProtectUtils.getStreamFromAssets("EncryptString.dex")));

        List<ClassDef> baseClassDefs = Lists.newArrayList(baseDex.getClasses());

        for (int i = 0; i < baseClassDefs.size(); i++) {
            try {
                dexBuilder.internClassDef(baseClassDefs.get(i));   //将EncrtptString.dex文件植入dexBuilder中
            } catch (Exception e) {
                e.printStackTrace();
            }
        }*/

        List<ClassDef> classDefs = Lists.newArrayList(dex.getClasses());


        for (int i = 0; i < classDefs.size(); i++) {

            ClassDef classDef = classDefs.get(i);
            dealClassDef(dexBuilder, classDef);   //处理dex中的class
            callBack.onProgress(i, classDefs.size());

        }


        MemoryDataStore memoryDataStore = new MemoryDataStore();
        dexBuilder.writeTo(memoryDataStore);
        out = Arrays.copyOf(memoryDataStore.getBufferData(), memoryDataStore.getSize());//内存拷贝到byte


        System.out.println("dex解密完成");
    }

    //解密class
    public void dealClassDef(DexBuilder dexBuilder, ClassDef classDef) {

        String type = classDef.getType();
        System.out.println(type);
        if (type.contains("AService")) {
            System.out.println("---debug");
        }
        callBack.onClassDefName(type);

        boolean isKeep = false;
        for (int l = 0; l < keeps.size(); l++) {   //处理的类是否为忽略的类
            if (type.startsWith(keeps.get(l))) {
                isKeep = true;
                break;
            } else {
                isKeep = false;
            }
        }


        if (isKeep) {
            innternClassDef(dexBuilder, classDef);
        } else {
            String smali = getSmaliByType(classDef);
            smali = dealSmali1(smali);
            // smali = dealSmali2(smali);
            try {
                Smali.assembleSmaliFile(smali, dexBuilder, new SmaliOptions()); //smali存入dexBuilder
                //dexBuilder.internClassDef(classDef);
            } catch (Exception e) {
                e.printStackTrace();
                if (!type.startsWith("LDecoder/")
                        && !type.startsWith("Lcom/ae/")) {
                    //return;
                }

                innternClassDef(dexBuilder, classDef);
            }
        }


    }


    public void innternClassDef(DexBuilder dexBuilder, ClassDef classDef) {
        try {
            dexBuilder.internClassDef(classDef);
        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    public byte[] getOutData() {
        return out;
    }

    public void save(String destPath) throws Exception {
        FileUtils.saveFile(out, destPath);
    }

    //处理smali文件中的字符串
    public String dealSmali1(String smali) {

        List<String> codes = new ArrayList<>();
        List<String> deCodes = new ArrayList<>();
        //找出参数类型 invoke前几行中，后面
        StringBuilder str = new StringBuilder();
        str.append(".+invoke-static(.+)");//找出本类是否执行 (,.+)(\n)+.+invoke-static(.+)
        str.append(decodeName.getSmaliStr().replace("(", "\\(").replace(")", "\\)"));
        Pattern tp = Pattern.compile(str.toString());
        Matcher tm = tp.matcher(smali);

        // Pattern p = Pattern.compile("(const-string\\sv([0-9]*),\\s\"(.*)\"\n)");


        String typecode = null;
        while (tm.find()) {
            String result = "";
            String enCode = "";
            //找出方法的前一代码,不包含line和空白
            String lastcode = getLastSmStr(smali, tm);
            typecode = lastcode.replaceAll("(.+),", "").trim();
            Log.i("SMALI", "dealSmali1: " + typecode);

            String type = lastcode.trim().split(" ")[1].replace(",", "");

            //  int v = Integer.parseInt(t);

            // typecode = tm.group().replaceAll("(.| \\h)+$","").trim().substring(1);


            try {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                    Class<?> DecodeClass = inMemoryDexClassLoader.loadClass(decodeName.getJClassName());
                    Class[] objects = decodeName.getParamsType(inMemoryDexClassLoader);

                    Method method = DecodeClass.getDeclaredMethod(decodeName.getJMethodName(), objects);

                    if (typecode.matches("(.)?0x.+")) {
                        //数值
                        // regx.append("(const-wide\\sv([0-9]*),\\s(.*))(.|\\n){2}(.+)");
                        //去掉0x和L
                        String ll = typecode.replaceFirst("0x", "").replace("L", "");
                        result = (String) method.invoke(null, Long.parseLong(ll, 16));
                    } else {
                        //字符
                        //regx.append("(const-string\\sv([0-9]*),\\s\\\"(.*)\\\")(.|\\n){2}(.+)");
                        result = (String) method.invoke(null, typecode);
                    }
                    //解密出来的数据中含有特殊字符json数据 转化为base64
                    if ( result.trim().startsWith("{")) {
                       // Toast.makeText(MyApplication.getContext(), "发现特殊字符,已经转换为base64", Toast.LENGTH_SHORT).show();
                        result = Base64Util.encode(result).replace("\n","");
                    }
                }

            } catch (Exception e) {
                e.printStackTrace();
                return  smali;
            }


            StringBuilder regx = new StringBuilder();
            regx.append(".*(");
            regx.append(lastcode.trim().replace("+", "\\+")); //处理含有+的情况
            regx.append(")(.*)(.*\\.line.*|\\n)+(.*)(.*\\.line.*|\\n)+(.*move.*)");
            //  ".+(const-string v3, \"P3GshB8hNJBBucAjKaxr6IlAnA==\")(.*)(.*\\.line.*|\\n)+(.*)(.*\\.line.*|\\n)+(.+)";
            Pattern pattern = Pattern.compile(regx.toString());
            Matcher matcher = pattern.matcher(smali);

            // String type = null;
            //判断最中的类型，当放入list时，是存入p寄存器中
            //    const-wide v2, -0x5cd3ea5b0c6L
            //
            //    invoke-static {v2, v3}, Le/a/a/a;->a(J)Ljava/lang/String;
            //
            //    move-result-object p1
            if (matcher.find()) {
                String deco = matcher.group();
                Matcher ma;
                if ((ma = Pattern.compile("( .+$)").matcher(deco.trim())).find()) {

                    String tmp =ma.group().trim().split(" ")[1];  //p1 v1
                    String regtye = tmp.substring(0,1); //p
                    int register = Integer.parseInt(tmp.replace("v", "").replace("p", ""));
                    if (tmp.equals(type)) {
                        //前后注册器一样时

                        if (register <= 15 && !typecode.equals("")) {
                            enCode = "const-string "+regtye + register + ",\"" + result + "\"\n";
                        }
                    } else {
                        //前后注册器不一样时

                        String regtye1 = type.substring(0,1);
                        int register1 = Integer.parseInt(type.replace("v", "").replace("p", ""));
                        enCode = "const-string "+regtye1 + register1 + ",\"" + result + "\"\n" +
                                "move-result-object "+regtye + register + "\n";
                    }
                }

            /* if (v > 15) {
                //enCode = smali;
            }*/
                //放入解密字符
                deCodes.add(enCode);
                //放入原本字符
                codes.add(deco);
            }


        }

/*
        regx.append(decodeName.getSmaliStr().replace("(","\\(").replace(")","\\)"));
        regx.append("(.|\\n){2}(.+)move-result-object(.+)");//(const-string\sv([0-9]*),\s\"(.*)\")(.|\n){2}(.+)(Lcom/ae/utils/Base64Util;->decode\(Ljava/lang/String;\)Ljava/lang/String;)(.|\n){2}move-result-object
        Pattern p = Pattern.compile(regx.toString());
        Matcher m = p.matcher(smali);
        while (m.find()) {
            String code = m.group();
            System.out.println(code);
            codes.add(code);
//(const-string\sv([0-9]*),\s\"(.*)\")(.|\n){2}(.+)(Lcom/ae/utils/Base64Util;->decode\(Ljava/lang/String;\)Ljava/lang/String;)(.|\n)+(move-result-object(.+)\n)
            int v = Integer.parseInt(m.group(2));
            String content = m.group(3);
            String enCode = "";

            try {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
              Class<?> DecodeClass = inMemoryDexClassLoader.loadClass(decodeName.getJClassName());
                    Class[] objects =decodeName.getParamsType(inMemoryDexClassLoader);

                    Method method =DecodeClass.getDeclaredMethod(decodeName.getJMethodName(),objects);

                    if (typecode.trim().matches("(.)?0x.+")){
                        //去掉0x和L
                        String ll =m.group(3).replaceFirst("0x","");
                        result = (String) method.invoke(null, Long.parseLong(ll.substring(0,ll.length()-1),16));
                    }else {
                        //字符
                        result = (String) method.invoke(null, m.group(3));
                    }

                }


            } catch (Exception e) {
                e.printStackTrace();
            }
            if (v <= 15 && !content.equals("")) {
                enCode = "const-string v" + v + ",\"" + result + "\"\n" ;
            }

            if (v > 15) {
                enCode = code;
            }

            deCodes.add(enCode);


        }

 */

        for (int a = 0; a < codes.size(); a++) {
            smali = smali.replace(codes.get(a), deCodes.get(a));
        }

        return smali;
    }


    public String dealSmali2(String smali) {

        List<String> codes = new ArrayList<>();
        List<String> enCodes = new ArrayList<>();

        Pattern p = Pattern.compile("(const-string\\sp([0-9]*),\\s\"(.*)\"\n)");
        Matcher m = p.matcher(smali);
        while (m.find()) {
            String code = m.group();
            System.out.println(code);
            codes.add(code);

            int v = Integer.parseInt(m.group(2));
            String content = m.group(3);
            String enCode = "";

            if (v <= 15) {
                enCode = "const-string p" + v + ",\"" + Base64Util.encode(content) + "\"\n" +
                        "invoke-static {p" + v + "}, Lcom/ae/utils/Base64Util;->decode(Ljava/lang/String;)Ljava/lang/String;\n" +
                        "move-result-object p" + v + "\n";
            }

            if (v > 15) {

                enCode = code;
            }

            enCodes.add(enCode);


        }

        for (int a = 0; a < codes.size(); a++) {
            smali = smali.replace(codes.get(a), enCodes.get(a));
        }

        return smali;
    }


    public static String getSmaliByType(ClassDef classDef) {
        String code = null;
        try {
            StringWriter stringWriter = new StringWriter();
            IndentingWriter writer = new IndentingWriter(stringWriter);
            ClassDefinition classDefinition1 = new ClassDefinition(new BaksmaliOptions(), classDef);
            classDefinition1.writeTo(writer);
            writer.close();
            code = stringWriter.toString();
        } catch (Exception e) {
            e.printStackTrace();
        }

        return code;
    }


    public interface EncryptCallBack {
        void onProgress(int progress, int total);

        void onClassDefName(String Name);
    }

    //获取smali上一行的代码,matcher:匹配的值，i: 行数
    public static String getLastSmStr(String str, Matcher matcher) {
        String[] lines = str.split("\r\n|\r|\n");
        String result = null;
        for (int j = mcurLines(str, matcher); j > 0; j--) {
            if (!lines[j - 1].contains(".line") && !lines[j - 1].contains(":try") && !lines[j - 1].contains(":goto") && !lines[j - 1].trim().equals("")) {
                result = lines[j - 1];
                break;
            }

        }
        return result;
    }

    public static String getNextSmStr(String str, Matcher matcher) {
        String[] lines = str.split("\r\n|\r|\n");
        String result = null;
        for (int j = mcurLines(str, matcher); j < lines.length; j++) {
            if (!lines[j - 1].contains(".line") && !lines[j - 1].contains(":try") && !lines[j - 1].contains(":goto") && !lines[j - 1].trim().equals("")) {
                result = lines[j - 1];
                break;
            }

        }
        return result;
    }

    public static class DecodeName {
        private String methodname; //Lcom/ae/utils/Base64Util/decode(Ljava/lang/String;)Ljava/lang/String;

        public DecodeName(String methodname) {
            this.methodname = methodname;
        }

        public String getLClassName() {
            //Lcom/ae/utils/Base64Util;
            return methodname.replaceAll("/(\\w*)[^/]\\((.*)\\)(.+)", "") + ";";
        }

        public String getLMethodName() {
            //decode(Ljava/lang/String;)Ljava/lang/String;
            return methodname.substring(methodname.split("(\\w*)[^/]\\((.*)\\)(.+)")[0].length());
        }

        public String getJClassName() {
            //com.ae.utils.Base64Util
            return getLClassName().substring(1, getLClassName().length() - 1).replace("/", ".");
        }

        public String getJMethodName() {
            //decode
            return getLMethodName().replaceAll("\\((.*)", "");
        }

        public Class[] getParamsType(ClassLoader classLoader) {

            try {
                Class<?> cls = classLoader.loadClass(getJClassName());
                for (Method declaredMethod : cls.getDeclaredMethods()) {
                    declaredMethod.setAccessible(true);
                    if (declaredMethod.getName().equals(getJMethodName())) {
                        return declaredMethod.getParameterTypes();
                    }

                }
            } catch (ClassNotFoundException e) {
                e.printStackTrace();
            }
            return null;
        }

        public String getSmaliStr() {
            //Lcom/ae/utils/Base64Util;->decode(Ljava/lang/String;)Ljava/lang/String;
            return getLClassName() + "->" + getLMethodName();
        }
    }

    private static int countLines(String str) {
        String[] lines = str.split("\r\n|\r|\n");
        return lines.length;
    }

    //matcher当前行数
    private static int mcurLines(String str, Matcher matcher) {
        int start = matcher.start();
        String result = str.substring(0, start);
        String[] lines = result.split("\r\n|\r|\n");
        return lines.length;
    }

    public static boolean isGoodJson(String json) {
        if (StringUtils.isBlank(json)) {
            return false;
        }
        try {
            new JsonParser().parse(json);
            return true;
        } catch (JsonParseException e) {
            return false;
        }
    }

}
