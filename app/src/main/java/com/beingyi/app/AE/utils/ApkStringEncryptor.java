package com.beingyi.app.AE.utils;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.io.IOException;
import java.util.zip.ZipOutputStream;
import java.io.FileOutputStream;

public class ApkStringEncryptor
{
    String Input;
    String Output;

    List<String> dexList = new ArrayList<String>();

    List<String> keeps;
    DexStringEncryptor.EncryptCallBack callBack;
    UICallBack uiCallBack;

    /**
     * Instantiates a new Apk string encryptor.
     *
     * @param input       apk路径
     * @param output      输出路径
     * @param keeps       the keeps
     * @param mCallBack   the m call back
     * @param mUICallBack the m ui call back
     */
    public ApkStringEncryptor(String input, String output, List<String> keeps, DexStringEncryptor.EncryptCallBack mCallBack,UICallBack mUICallBack)
    {
        this.Input = input;
        this.Output = output;
        this.keeps = keeps;
        this.callBack = mCallBack;
        this.uiCallBack=mUICallBack;

//Ctrl + Shift+/  /* */
        //Shift + Alt + g javadoc
    }


    public void start() throws Exception
    {

        ZipFile zipFile = new ZipFile(Input);
        HashMap<String, byte[]> zipEnties = new HashMap<String, byte[]>();
        ZipOutputStream zos=new ZipOutputStream(new FileOutputStream(Output));

        readZip(zipFile, zipEnties);

        for (String dexName : dexList)
        {
            uiCallBack.onStep("正在处理："+dexName);
            
            InputStream inputStream = zipFile.getInputStream(zipFile.getEntry(dexName));
            ByteArrayOutputStream baos = FileUtils.cloneInputStream(inputStream);

            //处理class.dex
            DexStringEncryptor dexStringEncryptor=new DexStringEncryptor(baos.toByteArray(), keeps, callBack);
            dexStringEncryptor.start();
            ZipOutUtil.AddFile(zos, dexName,dexStringEncryptor.getOutData());//将byte[] dexStringEncryptor.getOutData() 写入zos中

        }
        
        if(dexList.size()==0){
            System.out.println("安装包异常");
            return;
        }

        uiCallBack.onStep("正在保存资源");
        ZipOutUtil.Sava(zipFile, zos, dexList, new ZipOutUtil.ZipSavsCallback(){  //保存为apk

                @Override
                public void onStep(ZipOutUtil.Step step)
                {
                    
                }

                @Override
                public void onProgress(int progress, int total)
                {
                    uiCallBack.onSaveProgress(progress,total);
                }
            });
        
        System.out.println("apk处理完成");
        

    }

/**
 * 解析apk,将内容列表拷贝到map中，dex添加到dexList中
*/
    private void readZip(ZipFile zip, Map<String, byte[]> map) throws Exception
    {
        Enumeration enums = zip.entries();
        while (enums.hasMoreElements())
        {
            ZipEntry entry = (ZipEntry) enums.nextElement();
            String entryName = entry.getName();
            // System.out.println(entryName);
            if (entryName.startsWith("classes") && entryName.endsWith(".dex"))
            {
                dexList.add(entryName);
            }

            if (!entry.isDirectory())
            {
                map.put(entry.getName(), null);
            }
        }

    }






    public interface UICallBack {
        void onStep(String Name);
        void onSaveProgress(int progress, int total);
    }


}
