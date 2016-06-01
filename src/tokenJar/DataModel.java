/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package tokenJar;


import burp.IBurpExtenderCallbacks;
import com.google.common.collect.HashMultimap;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;
import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;
import javax.script.ScriptException;
import javax.swing.table.DefaultTableModel;


/**
 *
 * @author DanNegrea
 */
public class DataModel {
    
    private final DefaultTableModel tableModel;
    private List<HashMap<String, Integer>> tokensByName;
    private HashMultimap<String, Integer> tokensByPath;
    private Pattern[] patterns; //precompile the patterns for performance
    
    private boolean masterEnable = false;
    private boolean masterDebug = false;
    
    private IBurpExtenderCallbacks callbacks;
    private final PrintWriter stderr;    
    
    private final ScriptEngine JSengine;

    public DataModel(DefaultTableModel tableModel, IBurpExtenderCallbacks callbacks){
        this.tableModel = tableModel;
        this.callbacks = callbacks;  
        stderr = new PrintWriter(callbacks.getStderr());
        
        ScriptEngineManager manager = new ScriptEngineManager();
        JSengine = manager.getEngineByName("JavaScript");
    }
   
    public void init() {
        int rowIdCount = tableModel.getRowCount();
        //*DEBUG*/callbacks.printOutput("init() | rowIdCount="+rowIdCount);
        tokensByName = new ArrayList<>(4);              //each parameter type has his own HashMap
        tokensByName.add(0, new HashMap(rowIdCount));   //url
        tokensByName.add(1, new HashMap(rowIdCount));   //body
        tokensByName.add(2, new HashMap(rowIdCount));   //cookie
        tokensByName.add(3, new HashMap(rowIdCount));   //other
         
        tokensByPath = HashMultimap.create(rowIdCount, 3*rowIdCount);
        patterns = new Pattern[rowIdCount]; 
        //where = new boolean[rowIdCount][7]; //7 param types
        
        //*DEBUG*/callbacks.printOutput("init() 2 ");
        
        for(int rowId=0; rowId<rowIdCount; rowId++){
            // If enabled and name set and path set and regex set then add to tokensByName and tokensByPath
            Object enable = tableModel.getValueAt(rowId, 0);
            Object name = tableModel.getValueAt(rowId, 1);
            //Object eval = tableModel.getValueAt(rowId, 7); //not used
            Object regex = tableModel.getValueAt(rowId, 8);
            Object path = tableModel.getValueAt(rowId, 9);
            
            
            if( enable!=null && (boolean)enable && checkRow(rowId, false) ){                
                boolean updated = false;
                //*DEBUG*/callbacks.printOutput("init() 3 ");
                for (byte type=0; type<=3; type++)
                    if (isUpdatable(rowId, type)){
                        tokensByName.get(type).put(name.toString(), rowId);
                        //*DEBUG*/callbacks.printOutput("tokensByName.get("+type+").put("+tableModel.getValueAt(rowId, 1).toString()+","+ rowId+")");
                        updated = true;
                        //*DEBUG*/callbacks.printOutput("init() 4 ");
                    }
                
                if (updated) {                
                    tokensByPath.put(path.toString(), rowId);
                    //*DEBUG*/callbacks.printOutput("tokensByPath.put("+tableModel.getValueAt(rowId, 9).toString()+","+ rowId+")");
                    try{
                        patterns[rowId] = Pattern.compile(regex.toString());
                    }
                    catch(Exception ex){
                        callbacks.printError("regex.toString() "+regex.toString());
                        PrintWriter stderr = new PrintWriter(callbacks.getStderr());
                        ex.printStackTrace(stderr);
                    }
                }
            }
        }
        //*DEBUG*/callbacks.printOutput("end init()");        
    }

    /**
     * Basic check of a row: 'name', 'eval', 'regex', 'path' cannot be empty
     * If repair is true, reset 'eval' and 'path' to default values and return false
     * @param rowId
     * @param repair
     * @return
     */
    public boolean checkRow(int rowId, boolean repair){
        //*DEBUG*/callbacks.printOutput("init() 2 ");
        Object name = tableModel.getValueAt(rowId, 1);
        Object eval = tableModel.getValueAt(rowId, 7);
        Object regex = tableModel.getValueAt(rowId, 8);
        Object path = tableModel.getValueAt(rowId, 9);
        boolean repaired = false;

        if (repair && eval== null || eval.toString().trim().equals("")){
            tableModel.setValueAt("grp[1]", rowId, 7);
            repaired = true;
        }
        
        if (repair && path== null || path.toString().trim().equals("")){
            tableModel.setValueAt("*", rowId, 9);
            repaired = true;
        }
        
        if (repaired || name==null || name.toString().trim().equals("") || regex==null || regex.toString().trim().equals(""))
            return false;
        else
            return true;       
    }
    
    /*Returns the rowId id for the given name and type; tokensByName holds the last changed rowId for the specified type*/
    public Integer getByName(String name, byte type) {
        return tokensByName.get(type).get(name);
    }
    
    /*Returns the rowId ids for the given path*/
    public Set<Integer> getByPath(String path) {
        Set<Integer> byPath = tokensByPath.get(path);
        Set<Integer> byAllPath = tokensByPath.get("*");
        byPath.addAll(byAllPath);
        return byPath;
    }
    
    public int getRowCount(){
        return tableModel.getRowCount();
    }
    
    public boolean getEnable(int rowId) {
        return (boolean) tableModel.getValueAt(rowId, 0);
    }
    
    public String getName(int rowId) {
        return tableModel.getValueAt(rowId, 1).toString();
    }

    public String getValue(int rowId) {
        //*DEBUG*/ callbacks.printOutput("getValue("+rowId+")");
        //*DEBUG*/ callbacks.printOutput("="+tableModel.getValueAt(rowId, 6).toString());
        
        return tableModel.getValueAt(rowId, 6).toString();
    }

    public String getPath(int rowId) {
        return tableModel.getValueAt(rowId, 9).toString();
    }
    
    public String getRegex(int rowId) {
        return tableModel.getValueAt(rowId, 8).toString();
    }
    
    public Pattern getPattern(int rowId) {
        return patterns[rowId];
    }
    
    public boolean getDebug(int rowId) {
        return (boolean) tableModel.getValueAt(rowId, 10);
    }
    
    public void setValue(Integer rowId, String[] grpValues) {
        //*DEBUG*/ callbacks.printOutput("setValue("+rowId+","+value+")");
        try {
            String evalJS = tableModel.getValueAt(rowId, 7).toString();
            
            JSengine.put("grp", grpValues);            
            String value = JSengine.eval( evalJS ).toString(); //compute the value by evaluating JavaScript
            
            tableModel.setValueAt(value, rowId, 6); //set the actual value
            
            //the update was done for this parameter
            String paramName = tableModel.getValueAt(rowId, 1).toString();        
            //mark that the latest value is to be obtained from this rowId id
            for (byte type=0; type<=3; type++) // do this for each param type
                if (isUpdatable(rowId, type))
                    tokensByName.get(type).put(paramName, rowId);
        } catch (ScriptException ex) {
            callbacks.printError(ex.getMessage());
        } 
        
    }
    
    public void setMasterEnable(boolean value){
        masterEnable = value;
    }
    
    public boolean getMasterEnable(){
        return masterEnable;
    }
    
    public void setMasterDebug(boolean value){
        masterDebug = value;
    }
    
    public boolean getMasterDebug(){
        return masterDebug;
    }
    public boolean isUpdatable(int rowId, byte type) {
        //*DEBUG*/callbacks.printOutput("isUpdatable() 1 | rowId="+rowId+", type="+type);
        //*DEBUG*/callbacks.printOutput("isUpdatable() 2 | tableModel.getValueAt(rowId, 2 + type )="+tableModel.getValueAt(rowId, 2 + type ));
        if (type<=3)
            return (boolean) tableModel.getValueAt(rowId, 2 + type );
        else
            return (boolean) tableModel.getValueAt(rowId, 2 + 3 );
    }
}