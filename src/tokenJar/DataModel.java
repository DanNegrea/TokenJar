/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package tokenJar;


import burp.IBurpExtenderCallbacks;
import com.google.common.collect.HashMultimap;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;
import javax.swing.table.DefaultTableModel;

import org.mozilla.javascript.Context;
import org.mozilla.javascript.Scriptable;
import org.mozilla.javascript.ScriptableObject;

/**
 *
 * @author DanNegrea
 */
public class DataModel {

    private final DefaultTableModel tableModel;
    private List<HashMap<String, Integer>> tokensByType;
    private HashMultimap<String, Integer> tokensByPath;
    private Pattern[] patterns; //precompile the patterns for performance

    private boolean masterEnable = false;
    private boolean masterProxy = true;
    private boolean masterIntruder = true;
    private boolean masterRepeater = true;
    private boolean masterDebug = false;

    private IBurpExtenderCallbacks callbacks;
    private final PrintWriter stderr;

    private boolean[] valueUpdated;

    public DataModel(DefaultTableModel tableModel, IBurpExtenderCallbacks callbacks){
        this.tableModel = tableModel;
        this.callbacks = callbacks;
        stderr = new PrintWriter(callbacks.getStderr());
    }

    public void init() {
        int rowIdCount = tableModel.getRowCount();

        tokensByType = new ArrayList<>(10);              //each parameter type has its own HashMap
        tokensByType.add(0,  new HashMap(rowIdCount));   //Extract from Request     -> -1+1
        tokensByType.add(1,  new HashMap(rowIdCount));   //Extract from Reponse     -> 0+1
        tokensByType.add(2,  new HashMap(rowIdCount));   //header                   -> 1+1
        tokensByType.add(3,  new HashMap(rowIdCount));   //url                      -> 2+1
        tokensByType.add(4,  new HashMap(rowIdCount));   //body                     -> 3+1
        tokensByType.add(5,  new HashMap(rowIdCount));   //cookie                   -> 4+1
        tokensByType.add(6,  new HashMap(rowIdCount));   //other                    -> 5+1
        tokensByType.add(7,  new HashMap(rowIdCount));   //To Proxy                 -> 6+1
        tokensByType.add(8,  new HashMap(rowIdCount));   //To Repeater              -> 7+1
        tokensByType.add(9,  new HashMap(rowIdCount));   //To Intruder              -> 8+1

        tokensByPath = HashMultimap.create(rowIdCount, 3*rowIdCount);
        patterns = new Pattern[rowIdCount];
        //where = new boolean[rowIdCount][7]; //7 param types
        valueUpdated = new boolean[rowIdCount];


        for(int rowId=0; rowId<rowIdCount; rowId++){
            // If enabled and name set and path set and regex set then add to tokensByType and tokensByPath
            Object enable = tableModel.getValueAt(rowId, 0);
            Object name = tableModel.getValueAt(rowId, 1);
            //Object eval = tableModel.getValueAt(rowId, 7); //not used
            Object regex = tableModel.getValueAt(rowId, 14);
            Object path = tableModel.getValueAt(rowId, 15);


            if( enable!=null && (boolean)enable && checkRow(rowId, false) ){
                boolean updated = false;
                for (byte type=0; type<=9; type++)
                    if (isUpdatable(rowId, type)){
                        tokensByType.get(type).put(name.toString(), rowId);
                        //*DEBUG*/callbacks.printOutput("tokensByType.get("+type+").put("+tableModel.getValueAt(rowId, 1).toString()+","+ rowId+")");
                        updated = true;
                    }

                if (updated) {
                    tokensByPath.put(path.toString(), rowId);
                    try{
                        patterns[rowId] = Pattern.compile(regex.toString());
                    }
                    catch(Exception ex){
                        callbacks.printOutput("! Regex evaluation exception for "+regex.toString() );
                        PrintStream burpErr = new PrintStream(callbacks.getStderr());
                        ex.printStackTrace(burpErr);
                    }
                }
            }
            // No changed in values is signaled
            this.valueUpdated[rowId]=false;
        }
    }

    /**
     * Basic check of a row: 'name', 'eval', 'regex', 'path' cannot be empty
     * If repair is true, reset 'eval' and 'path' to default values and return false
     * @param rowId
     * @param repair
     * @return
     */
    public boolean checkRow(int rowId, boolean repair){
        Object name = tableModel.getValueAt(rowId, 1);
        Object eval = tableModel.getValueAt(rowId, 13);
        Object regex = tableModel.getValueAt(rowId, 14);
        Object path = tableModel.getValueAt(rowId, 15);
        boolean repaired = false;

        if (repair && eval== null || eval.toString().trim().equals("")){
            tableModel.setValueAt("grp[1]", rowId, 13);
            repaired = true;
        }

        if (repair && path== null || path.toString().trim().equals("")){
            tableModel.setValueAt("*", rowId, 15);
            repaired = true;
        }

        if (repaired || name==null || name.toString().trim().equals("") || regex==null || regex.toString().trim().equals(""))
            return false;
        else
            return true;
    }

    /*Returns the rowId id for the given name and type; tokensByType holds the last changed rowId for the specified type*/
    public Integer getByNameType(String name, byte type) {
        return tokensByType.get(type).get(name);
    }

    /*Returns the rowId ids for the given path*/
    public Set<Integer> getByPath(String path) {
        Set<Integer> byPath = tokensByPath.get(path);
        Set<Integer> byAllPath = tokensByPath.get("*");
        byPath.addAll(byAllPath);
        return byPath;
    }

    public boolean getFromRequest(int rowId) {
        return (boolean)tableModel.getValueAt(rowId, 2);
    }

    public boolean getFromResponse(int rowId) {
        return (boolean)tableModel.getValueAt(rowId, 3);
    }

    public boolean getToProxy(int rowId) {
        return (boolean)tableModel.getValueAt(rowId, 9);
    }

    public boolean getToRepeater(int rowId) {
        return (boolean)tableModel.getValueAt(rowId, 10);
    }

    public boolean getToIntruder(int rowId) {
        return (boolean)tableModel.getValueAt(rowId, 11);
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

        return tableModel.getValueAt(rowId, 12).toString();
    }

    public String getPath(int rowId) {
        return tableModel.getValueAt(rowId, 15).toString();
    }

    public String getRegex(int rowId) {
        return tableModel.getValueAt(rowId, 14).toString();
    }

    public Pattern getPattern(int rowId) {
        return patterns[rowId];
    }

    public void setValue(Integer rowId, String[] grpValues) {
        Context cx = Context.enter();
        try {
            String evalJS = tableModel.getValueAt(rowId, 13).toString();

            Scriptable scope = cx.initStandardObjects();

            //inject in JavaScript context the captured groups
            Object jsGrpValues = Context.javaToJS(grpValues, scope);
            ScriptableObject.putProperty(scope, "grp", jsGrpValues);

            //compute the value by evaluating JavaScript
            Object result = cx.evaluateString(scope, evalJS, "<evalJS>", 1, null);
            String value = Context.toString(result);

            this.valueUpdated[rowId]=true; //signal that the value was updated programatically
            tableModel.setValueAt(value, rowId, 12); //set the actual value

            //the update was done for this parameter
            String paramName = tableModel.getValueAt(rowId, 1).toString();
            //mark that the latest value is to be obtained from this rowId id
            for (byte type=0; type<=9; type++) // do this for each param type
                if (isUpdatable(rowId, type))
                    tokensByType.get(type).put(paramName, rowId);
        } catch (Exception ex) {
            callbacks.printError(ex.getMessage());
        } finally {
            Context.exit();
        }
    }

    /*The value was updated in the DataModel*/
    public boolean isValueUpdated(int rowId){
        if (this.valueUpdated[rowId]){
            // signal that the value vas updated (does not need any update)
            //and reset to false for next time
            this.valueUpdated[rowId]=false;
            return true;
        }
        return false;
    }
    public void setMasterEnable(boolean value){
        masterEnable = value;
    }

    public boolean getMasterEnable(){
        return masterEnable;
    }

    public void setMasterProxy(boolean value){
        masterProxy = value;
    }
    public boolean getMasterProxy(){
        return masterProxy;
    }

    public void setMasterIntruder(boolean value){
        masterIntruder = value;
    }
    public boolean getMasterIntruder(){
        return masterIntruder;
    }

    public void setMasterRepeater(boolean value){
        masterRepeater = value;
    }
    public boolean getMasterRepeater(){
        return masterRepeater;
    }

    public void setMasterDebug(boolean value){
        masterDebug = value;
    }

    public boolean getMasterDebug(){
        return masterDebug;
    }
    public boolean isUpdatable(int rowId, byte type) {
        //Attention: The order of parameter columns (checkboxes) in Table is important
        if (type<9)
            return (boolean) tableModel.getValueAt(rowId, 2 + type ); // 2 is the position of 'header'
                                                                      // header -> .getValueAt(_,2)
                                                                      // ...
                                                                      // cookie -> .getValueAt(_,5)
        else
            return (boolean) tableModel.getValueAt(rowId, 2 + 9 );    // other -> .getValueAt(_,6)
    }
}
