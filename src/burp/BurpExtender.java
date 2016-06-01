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
        //*DEBUG*/ callbacks.printOutput("processResponseMessage()");
        boolean debugPrintOnce = true;
        boolean matcherFound = false;
        
        //Obtaining path
    	IRequestInfo requestInfo = helpers.analyzeRequest(HTTP_message);
    	String path = requestInfo.getUrl().getPath();
        
        String HTTP_response = null;
        
        Set<Integer> ids = dataModel.getByPath( path );
        
        //*DEBUG*/ callbacks.printOutput("1 path = "+ path);
        //*DEBUG*/ callbacks.printOutput("2 ids.size() = "+ ids.size());
        
        for(Integer id: ids){                     
            //Get only the first time the response
            if (HTTP_response==null) HTTP_response = new String(HTTP_message.getResponse());
            String value = null;
            
            Matcher matcher = dataModel.getPattern(id).matcher( HTTP_response );
            int grpCount = matcher.groupCount()+1;
            
            //*DEBUG*/ callbacks.printOutput("3 grpCount= "+ grpCount);
            if (matcher.find()) { //do I need to test for && grpCount >=0 ?
                    String[] grpValues = new String[grpCount];
                    
                    for (int i=0; i<grpCount; i++){
                        grpValues[i]= matcher.group(i);
                        //*DEBUG*/ callbacks.printOutput("4 grpValues["+i+"]="+ grpValues[i]);
                    }                    
                    dataModel.setValue(id, grpValues);
                    
                    matcherFound = true;
            }
            
            //DEBUG enabled
            if (dataModel.getMasterDebug() && dataModel.getDebug(id)){
                if (debugPrintOnce){
                    callbacks.printOutput("");
                    callbacks.printOutput("<<< Processing Response Message");
                    callbacks.printOutput("< Path=" + path);
                    
                    if (HTTP_message.getComment()==null) HTTP_message.setComment("");
                    
                    if (matcherFound)                        
                        HTTP_message.setComment( HTTP_message.getComment() + " Tokens OUT ");
                    debugPrintOnce = false;
                }
                if (matcherFound) {
                    HTTP_message.setComment( HTTP_message.getComment() + dataModel.getName(id)+" ");
                    callbacks.printOutput("< Match for "+dataModel.getName(id)+"("+id+"), regex=" + dataModel.getRegex(id));                   
                }
                else
                    callbacks.printOutput("< No match for "+dataModel.getName(id)+"("+id+"), regex=" + dataModel.getRegex(id));
            }
            //end DEBUG
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
        class enhancedParameter{
            public enhancedParameter(IParameter IParam, String newValue){
                this.IParam = IParam;
                this.newvalue = newValue;
            }
            public IParameter IParam;
            public String newvalue;
        }
        
    	IRequestInfo requestInfo = helpers.analyzeRequest(HTTP_message);
    	byte[] oRequest = HTTP_message.getRequest();
        List<IParameter> oParameters = requestInfo.getParameters();
        List<enhancedParameter> nParameters = new ArrayList<>();
        
        //*DEBUG*/callbacks.printOutput("processRequestMessage() 1 path="+requestInfo.getUrl().getPath());
        
        Integer id;
        int deltaLenthReq=0;       
        int deltaLenthContent=0; 
        int delta; //work variable
        
        //1. Identify all params that are also in the table
        //2. Calculate Content-Length delta length 
        for (IParameter parameter : oParameters) {
            //*DEBUG*/callbacks.printOutput("processRequestMessage() 2 parameter.getName="+parameter.getName());
            byte parameterType = parameter.getType();
            if ( (id = dataModel.getByName(parameter.getName(), parameterType))!=null ) {
                String newValue = dataModel.getValue(id);
                
                //*DEBUG*/callbacks.printOutput("processRequestMessage() 3 id= "+id);
                            
                nParameters.add(new enhancedParameter(parameter, newValue));
                delta = newValue.length() - (parameter.getValueEnd() - parameter.getValueStart());
                deltaLenthReq += delta;
                
                //Update Content-Length only for certain parameters                
                if ( parameterType == IParameter.PARAM_BODY || 
                        parameterType == IParameter.PARAM_JSON || 
                        parameterType == IParameter.PARAM_MULTIPART_ATTR ||  
                        parameterType == IParameter.PARAM_XML || 
                        parameterType == IParameter.PARAM_XML_ATTR )
                    deltaLenthContent += delta;
            }
        }
        
        //*DEBUG*/callbacks.printOutput("processRequestMessage() 4");
        
        //EXIT if no parameter was found
        if (nParameters.isEmpty()){
            if (dataModel.getMasterDebug()){
                callbacks.printOutput("");
                callbacks.printOutput(">>> Processing Request Message");
                callbacks.printOutput("> Path=" + requestInfo.getUrl().getPath());
                callbacks.printOutput("> No parameters to update");
            }
            return;
        }
        
        //Content-Length preparation
        List<String> HTTP_headers = requestInfo.getHeaders();        
        int oContLenStart=0, oContLenLength=0, oContLenValue=0;
        boolean oContLenProccess = false;
                
        for(int i=0; i<HTTP_headers.size(); i++){
            //*DEBUG*/callbacks.printOutput("+++"+HTTP_headers.get(i));
            if ( HTTP_headers.get(i).contains("Content-Length:")) {
                String Content_Length = HTTP_headers.get(i);
                oContLenStart = Bytes.indexOf(oRequest, Content_Length.getBytes());
                oContLenLength = Content_Length.length();
                oContLenValue = Integer.parseInt(Content_Length.substring("Content-Length:".length()).trim());                
                //*DEBUG*/callbacks.printOutput("###oContLenStart="+oContLenStart+", oContLenLength="+oContLenLength+", oContLenValue="+oContLenValue);       
                
                oContLenProccess = true;
                break;
            }
        }
        //end Content-Length preparation
        
        byte[] nRequest = new byte[oRequest.length + deltaLenthReq];
        
        int oStart = 0;
        int oEnd = oRequest.length;
        int nStart = 0;
        int oParamStart, oParamEnd;
        //*DEBUG*/callbacks.printOutput("processRequestMessage() 5");
        //debug useful
        boolean debugPrintOnce = true;        
        String[] paramType = {"PARAM_URL", "PARAM_BODY", "PARAM_COOKIE", "PARAM_JSON", "PARAM_MULTIPART_ATTR", "PARAM_XML", "PARAM_XML_ATTR"};
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
            if (dataModel.getMasterDebug() && dataModel.getDebug(dataModel.getByName(parameter.IParam.getName(), parameter.IParam.getType()))){
                if (debugPrintOnce){
                    callbacks.printOutput("");
                    callbacks.printOutput(">>> Processing Request Message");
                    callbacks.printOutput("> Path=" + requestInfo.getUrl().getPath());
                    if (HTTP_message.getComment()==null) HTTP_message.setComment("");
                    HTTP_message.setComment( HTTP_message.getComment() + " Tokens IN ");
                    debugPrintOnce = false;
                }                
                callbacks.printOutput("> Updating "+parameter.IParam.getName()+" of type "+ paramType[parameter.IParam.getType()]);
                callbacks.printOutput("> Old possition start="+oStart );
                callbacks.printOutput("> New possition start="+nStart );
                callbacks.printOutput("> New value="+parameter.newvalue);
                HTTP_message.setComment( HTTP_message.getComment() + parameter.IParam.getName()+" ");
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
                callbacks.printError("processRequestMessage() arraycopy, path=" + requestInfo.getUrl().getPath() + ", oStart=" + oStart + ", nStart=" + nStart );
                PrintWriter stderr = new PrintWriter(callbacks.getStderr());
                ex.printStackTrace(stderr);
            }
            
        }
        //Send the new request 
        HTTP_message.setRequest(nRequest);
    } 
}
