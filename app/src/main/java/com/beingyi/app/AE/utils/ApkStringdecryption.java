package com.beingyi.app.AE.utils;

import android.widget.Toast;

import com.beingyi.app.AE.application.MyApplication;

import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TooManyListenersException;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipOutputStream;

import dalvik.system.InMemoryDexClassLoader;

/**
 * @ClassName com.beingyi.app.AE.utils
 * @Description
 * @Author xiaoping
 * @Date 2022/03/01
 * @Version 1.0
 */
public class ApkStringdecryption {
    String Input;
    String Output;
    String decodeMethod;
    List<String> dexList = new ArrayList<String>();

    List<String> keeps;
    DexStringEncryptor.EncryptCallBack callBack;
    ApkStringEncryptor.UICallBack uiCallBack;

    /**
     * Instantiates a new Apk string encryptor.
     *
     * @param input       apk路径
     * @param output      输出路径
     * @param keeps       the keeps
     * @param mCallBack   the m call back
     * @param mUICallBack the m ui call back
     */
    public ApkStringdecryption(String input, String output, List<String> keeps, String DecodeM, DexStringEncryptor.EncryptCallBack mCallBack, ApkStringEncryptor.UICallBack mUICallBack) {
        this.Input = input;
        this.Output = output;
        this.keeps = keeps;
        this.callBack = mCallBack;
        this.uiCallBack = mUICallBack;
        this.decodeMethod = DecodeM;
//Ctrl + Shift+/  /* */
        //Shift + Alt + g javadoc
    }


    public void start() throws Exception {

        ZipFile zipFile = new ZipFile(Input);
        HashMap<String, byte[]> zipEnties = new HashMap<String, byte[]>();
        ZipOutputStream zos = new ZipOutputStream(new FileOutputStream(Output));

        readZip(zipFile, zipEnties);

        for (String dexName : dexList) {
            uiCallBack.onStep("正在处理：" + dexName);

            InputStream inputStream = zipFile.getInputStream(zipFile.getEntry(dexName));
            ByteArrayOutputStream baos = FileUtils.cloneInputStream(inputStream);

            InMemoryDexClassLoader inMemoryDexClassLoader = null;
            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O) {
                inMemoryDexClassLoader = new InMemoryDexClassLoader(byte2Byffer(baos.toByteArray()), null);
            } else {
                Toast.makeText(MyApplication.getContext(), "需要8.0以上才能使用", Toast.LENGTH_SHORT).show();
            }


            //处理class.dex
            DexStringDecryption dexStringDecryption = new DexStringDecryption(baos.toByteArray(), keeps, decodeMethod, inMemoryDexClassLoader, callBack);
            dexStringDecryption.start();
            ZipOutUtil.AddFile(zos, dexName, dexStringDecryption.getOutData());//将byte[] dexStringEncryptor.getOutData() 写入zos中

        }

        if (dexList.size() == 0) {
            System.out.println("安装包异常");
            return;
        }

        uiCallBack.onStep("正在保存资源");
        ZipOutUtil.Sava(zipFile, zos, dexList, new ZipOutUtil.ZipSavsCallback() {  //保存为apk

            @Override
            public void onStep(ZipOutUtil.Step step) {

            }

            @Override
            public void onProgress(int progress, int total) {
                uiCallBack.onSaveProgress(progress, total);
            }
        });

        System.out.println("apk处理完成");


    }

    /**
     * 解析apk,将内容列表拷贝到map中，dex添加到dexList中
     */
    private void readZip(ZipFile zip, Map<String, byte[]> map) throws Exception {
        Enumeration enums = zip.entries();
        while (enums.hasMoreElements()) {
            ZipEntry entry = (ZipEntry) enums.nextElement();
            String entryName = entry.getName();
            // System.out.println(entryName);
            if (entryName.startsWith("classes") && entryName.endsWith(".dex")) {
                dexList.add(entryName);
            }

            if (!entry.isDirectory()) {
                map.put(entry.getName(), null);
            }
        }

    }


    /**
     * byte 数组转byteBuffer
     *
     * @param byteArray
     */
    public static ByteBuffer byte2Byffer(byte[] byteArray) {

        //初始化一个和byte长度一样的buffer
        ByteBuffer buffer = ByteBuffer.allocate(byteArray.length);
        // 数组放到buffer中
        buffer.put(byteArray);
        //重置 limit 和postion 值 否则 buffer 读取数据不对
        buffer.flip();
        return buffer;
    }

    /**
     * byteBuffer 转 byte数组
     *
     * @param buffer
     * @return
     */
    public static byte[] bytebuffer2ByteArray(ByteBuffer buffer) {
        //重置 limit 和postion 值
        buffer.flip();
        //获取buffer中有效大小
        int len = buffer.limit() - buffer.position();

        byte[] bytes = new byte[len];

        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = buffer.get();

        }

        return bytes;
    }

    public interface UICallBack {
        void onStep(String Name);

        void onSaveProgress(int progress, int total);
    }


}
