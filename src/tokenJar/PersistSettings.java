/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package tokenJar;

import burp.IBurpExtenderCallbacks;
import com.google.common.base.Strings;
import com.google.common.collect.EvictingQueue;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.PrintWriter;
import java.util.Vector;

/**
 *
 * @author DanNegrea
 */
public class PersistSettings {    
    private EvictingQueue<String> evalQueue;
    private EvictingQueue<String> regexQueue;
    
    private final IBurpExtenderCallbacks callbacks;
    
    public PersistSettings(IBurpExtenderCallbacks callbacks){
            this(callbacks, 50);
    }
    
    public PersistSettings(IBurpExtenderCallbacks callbacks, int expMaxSize){        
        this.evalQueue = EvictingQueue.create(expMaxSize);        
        this.regexQueue = EvictingQueue.create(expMaxSize);        
        this.callbacks = callbacks;
    }
       
    public void save(Vector dataInTable){
        try (
            ByteArrayOutputStream byteArrOut = new ByteArrayOutputStream();
            ObjectOutputStream objectOut = new ObjectOutputStream(byteArrOut);
        ){       
            objectOut.writeObject(dataInTable);
            callbacks.saveExtensionSetting("dataInTable", byteArrOut.toString());  //Java-Lesson objectOut is not suitable here
        } catch (IOException ex) {
            PrintWriter stderr = new PrintWriter(callbacks.getStderr());
            ex.printStackTrace(stderr);
        }
        save(evalQueue, "evalQueue");
        save(regexQueue, "regexQueue");
    }
    private void save(EvictingQueue<String> queue, String queueName){
        try (
            ByteArrayOutputStream byteArrOut = new ByteArrayOutputStream();
            ObjectOutputStream objectOut = new ObjectOutputStream(byteArrOut);
        ){            
            objectOut.writeObject(queue);
            callbacks.saveExtensionSetting(queueName, byteArrOut.toString());
        } catch (IOException ex) {
            PrintWriter stderr = new PrintWriter(callbacks.getStderr());
            ex.printStackTrace(stderr);
        }
    }
    
    public Vector restore(){        
        String tableData= callbacks.loadExtensionSetting("dataInTable");
        Vector dataInTable = null;
        
        if (tableData == null)  return null;
        
        try (
            ByteArrayInputStream byteArrIn = new ByteArrayInputStream(tableData.getBytes());
            ObjectInputStream objectIn = new ObjectInputStream(byteArrIn);
        ){  
            //get data in table from the serialized object
            dataInTable = (Vector) objectIn.readObject();
            
            //second objective, attempt to restore the evalQueue and regexQueue
            evalQueue = restore(evalQueue, "evalQueue");
            regexQueue = restore(regexQueue, "regexQueue");
            
        } catch (IOException | ClassNotFoundException ex) {
            PrintWriter stderr = new PrintWriter(callbacks.getStderr());
            ex.printStackTrace(stderr);
        }
        finally{
             return dataInTable;
        }     
    }
    
    private EvictingQueue<String> restore(EvictingQueue<String> queue, String queueName){
        String storedStr= callbacks.loadExtensionSetting(queueName);        
        if (storedStr == null)  return queue;
        
        EvictingQueue<String> newQueue=null;
        try (
            ByteArrayInputStream byteArrIn = new ByteArrayInputStream(storedStr.getBytes());
            ObjectInputStream objectIn = new ObjectInputStream(byteArrIn);
        ){  
            newQueue = (EvictingQueue<String>) objectIn.readObject();            
        } 
        catch (IOException | ClassNotFoundException ex) {
            PrintWriter stderr = new PrintWriter(callbacks.getStderr());
            ex.printStackTrace(stderr);
        }
        finally{
            if (newQueue==null) return queue; 
            else return newQueue;
        }     
    }   
    
    public void pushEval(String expression){
        if( !Strings.isNullOrEmpty(expression) ){
            if (evalQueue.contains(expression)){ 
                evalQueue.remove(expression);
            }
            evalQueue.add(expression);            
        }
    }
    public Object[] getEval(){        
        if (evalQueue.size()>0)
           return evalQueue.toArray();
        else
            return new Object[0];
    }
    public void pushRegex(String expression){
        if( !Strings.isNullOrEmpty(expression) ){
            //if expression is contained, remove it and add it fresh
            if (regexQueue.contains(expression)) 
               regexQueue.remove(expression);     
            regexQueue.add(expression);            
        }
    }
    public Object[] getRegex(){
        if (regexQueue.size()>0)
           return regexQueue.toArray();
        else
            return new Object[0];
    }  
}

