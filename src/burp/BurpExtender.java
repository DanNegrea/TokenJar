package burp;

import com.google.common.primitives.Bytes; //Guava
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import tokenJar.*;

public class BurpExtender implements IBurpExtender, IHttpListener, IProxyListener, IExtensionStateListener
{
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private Tab tab;
    private DataModel dataModel;
    
    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks){
        this.callbacks = callbacks;
        helpers = callbacks.getHelpers();
        
        // Set extension name
        callbacks.setExtensionName("TokenJar 1.0 tracking tokens: antiCSRF or CSurf, special seesion values...");
        
        tab = new Tab(callbacks);
        dataModel = tab.getDataModel();
              
        callbacks.customizeUiComponent(tab);
        callbacks.addSuiteTab(tab);
        
        // Register as listener
        callbacks.registerHttpListener(this);
        callbacks.registerProxyListener(this);
        callbacks.registerExtensionStateListener(this);  
    }
    
    /*
    // IExtensionStateListener implementation 
    */    
    @Override
    public void extensionUnloaded(){
        ;//dataModel is no longer accessible at this point
    }
    
    /* 
    // IProxyListener implementation
    */
    @Override
    public void processProxyMessage( boolean isRequest, IInterceptedProxyMessage message){
        //EXIT if Master Enable button is disabled
        if (dataModel.getMasterEnable()==false)
            return;
        if (dataModel.getMasterProxy()==false)
            return;
        
    	IHttpRequestResponse OLD_message = message.getMessageInfo();
    	if (isRequest) {
    		processRequestMessage(OLD_message);
    	} else {
    		processResponseMessage(OLD_message);    		
    	}
    	message.setInterceptAction(IInterceptedProxyMessage.ACTION_FOLLOW_RULES);
    }
    
    /*
    // IHttpListener implementation
    */
    @Override
    public void processHttpMessage(int toolFlag, boolean isRequest, IHttpRequestResponse message){
        //EXIT, it was already proccessed by PROXY
        if (toolFlag == IBurpExtenderCallbacks.TOOL_PROXY)
           return;
        
        //EXIT if Master Enable button is disabled
        if (dataModel.getMasterEnable()==false)
            return;
        if (dataModel.getMasterIntruder()==false && toolFlag == IBurpExtenderCallbacks.TOOL_INTRUDER)
            return;
        if (dataModel.getMasterRepeater()==false && toolFlag == IBurpExtenderCallbacks.TOOL_REPEATER)
            return;
       
    	if (isRequest){
    		processRequestMessage(message);
    	} else {
    		processResponseMessage(message);    		
    	}
    }
   
    /* 
    // Response message
    */
    private void processResponseMessage(IHttpRequestResponse HTTP_message) 
    {        
        try{
        
        //Obtaining path
    	IRequestInfo requestInfo = helpers.analyzeRequest(HTTP_message);
    	String path = requestInfo.getUrl().getPath();
        
        //Debug enabled
        if (dataModel.getMasterDebug()){
            callbacks.printOutput("");
            callbacks.printOutput("<<< Processing Response Message");
            callbacks.printOutput(". Path=" + path);
            if (HTTP_message.getComment()==null)
                HTTP_message.setComment("Tokenjar:");
        }
        
        String HTTP_response = null;
        //get all ids for token that 'listen' for this response
        Set<Integer> ids = dataModel.getByPath( path );
                
        for(Integer id: ids){                     
            //Get only the first time the response
            if (HTTP_response==null) HTTP_response = new String(HTTP_message.getResponse());
            String value = null;
            
            Matcher matcher = dataModel.getPattern(id).matcher( HTTP_response );
            int grpCount = matcher.groupCount()+1;   
            
            if (matcher.find()) { //do I need to test for && grpCount >=0 ?                
                   /*Debug enabled*/
                    if (dataModel.getMasterDebug()) {
                        HTTP_message.setComment( HTTP_message.getComment() + " match:"+dataModel.getName(id));                        
                        callbacks.printOutput(". Match for "+dataModel.getName(id)+" (rule "+id+") for Regex=" + dataModel.getRegex(id));                   
                    }
                    String[] grpValues = new String[grpCount];
                    
                    for (int i=0; i<grpCount; i++){
                        grpValues[i]= matcher.group(i);                        
                        /*Debug enabled*/
                        if (dataModel.getMasterDebug()){ 
                            callbacks.printOutput("+ grp["+i+"]="+ grpValues[i]);
                        }
                    }                    
                    dataModel.setValue(id, grpValues);
            } 
            else 
                /*Debug enabled*/
                if (dataModel.getMasterDebug()){ 
                    callbacks.printOutput("< No match for "+dataModel.getName(id)+"("+id+"), regex=" + dataModel.getRegex(id));
                }
        }
        }catch (Exception ex){
            callbacks.printError("ERR2");
            PrintWriter stderr = new PrintWriter(callbacks.getStderr());
            ex.printStackTrace(stderr);
        }
    }
    /* 
    // Request message
    */
    private void processRequestMessage(IHttpRequestResponse HTTP_message){
        
    	IRequestInfo requestInfo = helpers.analyzeRequest(HTTP_message);
    	byte[] oRequest = HTTP_message.getRequest();
        List<IParameter> oParameters = requestInfo.getParameters();
        List<enhancedParameter> nParameters = new ArrayList<>();
        
        //*DEBUG*/callbacks.printOutput("processRequestMessage() 1 path="+requestInfo.getUrl().getPath());
        
        Integer id;
        int deltaLenthReq=0;       
        int deltaLenthContent=0; 
        int delta; //work variable
        
        //Debug enabled
        if (dataModel.getMasterDebug()){
                callbacks.printOutput("");
                callbacks.printOutput(">>> Processing Request Message");
                callbacks.printOutput(". Path=" + requestInfo.getUrl().getPath());
                if (HTTP_message.getComment()==null)
                    HTTP_message.setComment("Tokenjar:");
        }
        
        //1. Identify all params that are also in the table
        //2. Calculate Content-Length delta length 
        for (IParameter parameter : oParameters) {
            if (dataModel.getMasterDebug()) {callbacks.printOutput(". Parameter["+parameter.getName()+"]="+parameter.getValue()+" of Type="+enhancedParameter.type.get(parameter.getType()));} /*Debug enabled*/
            
            // the parameter type must be between 0 and 3
            byte parameterType = parameter.getType();
            if (parameterType>3)
                parameterType = 3;
            
            if ( (id = dataModel.getByName(parameter.getName(), parameterType))!=null ) {
                String newValue = dataModel.getValue(id);
                            
                nParameters.add(new enhancedParameter(parameter, newValue));
                delta = newValue.length() - (parameter.getValueEnd() - parameter.getValueStart());
                deltaLenthReq += delta;
                
                //Update Content-Length only for body parameters
                if ( parameterType == IParameter.PARAM_BODY || 
                        parameterType >= 3 ) /*other parameter type*/
                    deltaLenthContent += delta;
            }
        }        
        //EXIT if no parameter was found
        if (nParameters.isEmpty()){
            if (dataModel.getMasterDebug()){callbacks.printOutput("= No parameters to update");}; //Debug enabled
            return;
        }
        
        //Content-Length preparation
        List<String> HTTP_headers = requestInfo.getHeaders();        
        int oContLenStart=0, oContLenLength=0, oContLenValue=0;
        boolean oContLenProccess = false;
                
        for(int i=0; i<HTTP_headers.size(); i++){
            
            if (dataModel.getMasterDebug()) {callbacks.printOutput(". Header["+i+"]="+HTTP_headers.get(i));} /*Debug enabled*/
            
            if ( HTTP_headers.get(i).startsWith("Content-Length:")) {
                String Content_Length = HTTP_headers.get(i);
                try {                    
                    oContLenStart = Bytes.indexOf(oRequest, Content_Length.getBytes());
                    oContLenLength = Content_Length.length();
                    oContLenValue = Integer.parseInt(Content_Length.substring("Content-Length:".length()).trim());                
                    //*DEBUG*/callbacks.printOutput("###oContLenStart="+oContLenStart+", oContLenLength="+oContLenLength+", oContLenValue="+oContLenValue);       
                
                    oContLenProccess = true;
                    break;
                }
                catch (NumberFormatException e){
                    // do nothing, let the for search for another "Content-Length" header
                    // if none was found the oContLenProccess shold be false
                    if (dataModel.getMasterDebug()){  /*Debug enabled*/
                        callbacks.printOutput("! NumberFormatException when converting "+Content_Length );
                        callbacks.printOutput("! skipped updating this header ");
                    }
                }
            }
        }
        //end Content-Length preparation
        
        byte[] nRequest = new byte[oRequest.length + deltaLenthReq];
        
        int oStart = 0;
        int oEnd = oRequest.length;
        int nStart = 0;
        int oParamStart, oParamEnd;
             
        //1. Update all parameters identified above
        //2. Update the Content-Length
        for (enhancedParameter parameter : nParameters) {             
            oParamStart  = parameter.IParam.getValueStart();
            oParamEnd = parameter.IParam.getValueEnd();
            
            //*DEBUG*/callbacks.printOutput("processRequestMessage() 6");
            
            //Content-Length update
            if (oContLenProccess && oParamStart > oContLenStart){ //found the parameter just after Content-Length?
                //copy everithing before the Content-Length
                delta = oContLenStart-oStart; 
                System.arraycopy(oRequest, oStart, nRequest, nStart, delta);
                oStart+= delta;
                nStart+= delta;
                
                //Compute and append the new Content-Length
                String nContLen = "Content-Length: "+ ((int) oContLenValue + (int) deltaLenthContent);
                
                if (dataModel.getMasterDebug()) {callbacks.printOutput("+ Content-Length="+ ((int) oContLenValue + (int) deltaLenthContent));} /*Debug enabled*/
                
                int nContLenLength = nContLen.length();
                System.arraycopy(nContLen.getBytes(), 0, nRequest, nStart, nContLenLength);
                //*DEBUG*/callbacks.printOutput("###nStart="+nStart+", nContLenLength="+nContLenLength);       
                oStart+= oContLenLength;
                nStart+= nContLenLength;
                //Content-Lenght updated
                oContLenProccess = false;
            }
            //end Content-Length update

            //copy everithing before the parameter
            delta = oParamStart-oStart;
            //*DEBUG*/callbacks.printOutput("###oStart="+oStart+", nStart="+nStart+", delta="+delta); 
            System.arraycopy(oRequest, oStart, nRequest, nStart, delta);
            oStart+= delta;
            nStart+= delta;
            
            //DEBUG enabled
            if (dataModel.getMasterDebug()){
                // the parameter type must be between 0 and 3
                byte parameterType = parameter.IParam.getType();
                if (parameterType>3)
                    parameterType = 3;
                           
                callbacks.printOutput("+ Parameter["+parameter.IParam.getName()+"]="+parameter.newvalue+" of Type="+ enhancedParameter.type.get(parameterType));
                HTTP_message.setComment( HTTP_message.getComment() + " new:" + parameter.IParam.getName()+" ");                
            }
            //end DEBUG

            int nParamLenght = parameter.newvalue.length();
            
            //Copying new value (might be empty, smaller or larger)
            System.arraycopy(parameter.newvalue.getBytes(), 0, nRequest, nStart, nParamLenght);
            //A better alternative?
            //Bytes.concat(byte[]... arrays);

            oStart+= oParamEnd-oParamStart;
            nStart+= nParamLenght;
        }
        
        //Copying till the end
        if (oStart>0 && oStart<oEnd){
            try{
                System.arraycopy(oRequest, oStart, nRequest, nStart, oEnd-oStart); 

            }catch (Exception ex){
                callbacks.printOutput("! arraycopy exception on path=" + requestInfo.getUrl().getPath() + ", oStart=" + oStart + ", nStart=" + nStart );                
                PrintWriter stderr = new PrintWriter(callbacks.getStderr());
                ex.printStackTrace(stderr);
            }
            
        }
        //Send the new request 
        HTTP_message.setRequest(nRequest);
    } 
}

class enhancedParameter{
    public static List<String> type;
    static {        
        type = new ArrayList(7);
        type.add(IParameter.PARAM_URL, "url");
        type.add(IParameter.PARAM_BODY, "body");
        type.add(IParameter.PARAM_COOKIE, "cookie");
        type.add(IParameter.PARAM_XML, "xml");
        type.add(IParameter.PARAM_XML_ATTR, "xml attr");
        type.add(IParameter.PARAM_MULTIPART_ATTR, "multipart attr");
        type.add(IParameter.PARAM_JSON, "json");
    }

    public enhancedParameter(IParameter IParam, String newValue){
        this.IParam = IParam;
        this.newvalue = newValue;
    }
    public IParameter IParam;
    public String newvalue;
}
