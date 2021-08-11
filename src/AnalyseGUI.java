//https://www.virustotal.com/gui/file/35cf775efe9f4cfb8413f324694f4d9fadea496611de583f2c4da7bc00201208/detection

import javax.swing.*;
import javax.swing.event.HyperlinkEvent;
import javax.swing.event.HyperlinkListener;
import javax.swing.text.DefaultCaret;
import java.awt.*;
import java.io.*;

import org.apache.http.HttpEntity;
import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.mime.MultipartEntityBuilder;
import org.apache.http.entity.mime.content.FileBody;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import java.util.*;
import java.util.List;

public class AnalyseGUI extends JDialog {
    protected File currentFile;
    protected String apiKey;
    protected String hashSHA256;
    protected String filePath;

    protected String filesURL;
    protected String filesUrlPOST;
    protected String urlAnalyseID;
    protected String uploadURL;
    protected String postURL;
    protected String jsonResultString;

    protected CloseableHttpClient httpclient;
    protected HttpGet requestHTTPGet;
    protected HttpPost requestHTTPPost;
    protected CloseableHttpResponse response;
    protected HttpEntity entity;

    protected JSONParser parser;
    protected JSONObject jsonResultJSON;


    private JPanel resultPanel;
    private JScrollPane resultScrollPane;
    private JTextPane resultTextPane;

    public AnalyseGUI(String url) throws IOException, ParseException {
        setVariables(url);

        createAndShowGUI();
        doResearch();
    }

    private void createAndShowGUI() {
        //https://stackoverflow.com/questions/34778965/how-to-remove-auto-focus-in-swing
        //getContentPane().requestFocusInWindow(); //leave the default focus to the JFrame
        setTitle("Virus Total Checker: ");
        setVisible(true);//making the frame visible
        setResizable(false);//not resizable, fixed
        setSize(700, 700);
        setLocationRelativeTo(null);//center
        setLayout(new BorderLayout());//BorderLayout est déjà par défaut

        resultPanel = new JPanel();
        resultScrollPane = new JScrollPane();
        resultTextPane = new JTextPane();
        resultTextPane.setEditable(false);
        resultTextPane.setContentType("text/html");
        DefaultCaret caret = (DefaultCaret) resultTextPane.getCaret();
        caret.setUpdatePolicy(DefaultCaret.NEVER_UPDATE);

        resultScrollPane.setViewportView(resultTextPane);
        resultScrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_ALWAYS);
        resultScrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);
        resultScrollPane.setPreferredSize(new Dimension(500, 500));

        resultPanel.add(resultScrollPane, BorderLayout.NORTH);
        add(resultPanel);

        resultTextPane.addHyperlinkListener(new HyperlinkListener() {
            @Override
            public void hyperlinkUpdate(HyperlinkEvent e) {
                if (e.getEventType() == HyperlinkEvent.EventType.ACTIVATED) {
                    openURI(e.getURL().toString());
                }
            }
        });

    }


    private void doResearch() throws IOException, ParseException {

        //First, check if a file already exist in VT Database
        //because it check the hash, being an special url or not doesn't matter
        if(alreadyExistGET(1, null)) {
            //System.out.println("File already exist in DT Database");
            try {
                entity = response.getEntity();

                if (entity != null) {
                    jsonResultString = EntityUtils.toString(entity);
                    jsonResultJSON = (JSONObject) parser.parse(jsonResultString);
                    JSONObject data = (JSONObject) jsonResultJSON.get("data");
                    JSONObject attributes = (JSONObject) data.get("attributes");
                    JSONArray names = (JSONArray) attributes.get("names");
                    String namesFile = "";
                    for (int i = 0; i < names.size(); i++) {
                        namesFile += "  "+names.get(i);
                    }

                    JSONObject lastAnalyseStats = (JSONObject) attributes.get("last_analysis_stats");
                    JSONObject lastAnalysisResult = (JSONObject) attributes.get("last_analysis_results");
                    String analysRes = "<strong>AntiVirus analyse</strong>: <br/>";
                    int o = analysRes.length();

                    Map<String, String> arrScanRes = new HashMap<>();
                    for (Object key : lastAnalysisResult.keySet()) {
                        String keyName = (String) key;//threat name
                        JSONObject obj2 = (JSONObject) lastAnalysisResult.get(key);//associated key result

                        String res = (String) obj2.get("result");
                        if(res != null) {
                            analysRes += "<strong>THREAT </strong><i>" + keyName + "</i> <strong>RESULT </strong><i>" + res + " </i><br/>";
                        }
                    }
                    if(analysRes.length() == o) {
                        analysRes += "EMPTY<br/>";
                    }

                    String result =
                                    "<strong>Malicious</strong>:  " + lastAnalyseStats.get("malicious")    + "<br/>"+
                                    "<strong>Harmless</strong>: " + lastAnalyseStats.get("harmless")   + "<br/>"+
                                    "<strong>Undetected</strong>: " + lastAnalyseStats.get("undetected")   + "<br/>"+
                                    "<strong>File Name(s)</strong>: " + namesFile   + "<br/>"+
                                    "<strong>SHA256</strong>:     " + hashSHA256       + "<br/>"+
                                    "<strong>Link</strong>: <a href='" + "https://www.virustotal.com/gui/file/" + hashSHA256  + "/detection'>here</a><br/><br/>"+
                                    analysRes;

                    resultTextPane.setText(result);

                    EntityUtils.consume(entity);
                }
            }catch(Exception e) {
                System.out.println(e.getMessage());
            }

            //Doesn't exist in VT Database
        }else {
            //System.out.println("File doesn't exist in the DT Database");
            /*2 use-case:
                -file <= 32MB
                    -> https://www.virustotal.com/api/v3/files
                      First, you have to upload the file to virustotal
                      -> POST - requiere 'x-apikey' and 'file=' parameters
                      The result returned by this endpoint is the object descriptor.
                      The ID contained can be used with the GET /analyses/{id} endpoint to get information about the analysis.
                         --> https://developers.virustotal.com/v3.0/reference#analysis
                         Retrieve information about a file or URL analysis
                         --> GET - https://www.virustotal.com/api/v3/analyses/id

                -file > 32MB
                      First, you will have to obtain a special URL from virustotal
                      -> https://www.virustotal.com/api/v3/files/upload_url (https://developers.virustotal.com/v3.0/reference#files-upload-url)
                      -> GET - requiere 'x-apikey'
                          -> "https://www.virustotal.com/api/v3/urls" (https://developers.virustotal.com/v3.0/reference#url)
                          -> POST - requiere 'x-apikey' and 'url='
                            The result returned by this endpoint is the object descriptor.
                            The ID contained can be used with the GET /analyses/{id} endpoint to get information about the analysis.
                               --> https://developers.virustotal.com/v3.0/reference#analysis
                               Retrieve information about a file or URL analysis
                               --> GET - https://www.virustotal.com/api/v3/analyses/id
             */

            //Check file size
            //-file <= 32MB
            if (checkFileSize(currentFile, 32)) {
                //System.out.println("File is less or equal 32mb");
                //upload file
                JSONObject postRes = uploadFilePOST();
                JSONObject error = (JSONObject) postRes.get("error");

                String errorRes = "";
                try {
                    errorRes = (String) error.get("code");
                }catch(Exception e) {
                    //
                }

                if (postRes != null && !errorRes.equals("WrongCredentialsError")) {
                    JSONObject data = (JSONObject) postRes.get("data");
                    //recover the special URL
                    String idAnalyse = (String) data.get("id");
                    //200
                    if (alreadyExistGET(2, idAnalyse)) {
                        entity = response.getEntity();

                        if (entity != null) {
                            // return it as a String
                            jsonResultString = EntityUtils.toString(entity);
                            jsonResultJSON = (JSONObject) parser.parse(jsonResultString);

                            data = (JSONObject) jsonResultJSON.get("data");
                            JSONObject attributes = (JSONObject) data.get("attributes");
                            String status = (String) attributes.get("status");
                            JSONObject stats = (JSONObject) attributes.get("stats");
                            JSONObject meta = (JSONObject) jsonResultJSON.get("meta");
                            JSONObject nameFile = (JSONObject) meta.get("file_info");

                            String result =
                                    "<strong>Malicious</strong>:  <i>" + stats.get("malicious") + "</i><br/>" +
                                            "<strong>Undetected</strong>: <i>" + stats.get("undetected") + "</i><br/>" +
                                            "<strong>Suspicious</strong>: <i>" + stats.get("suspicious") + "</i><br/>" +
                                            "<strong>File Name(s)</strong>:  <i>" + nameFile.get("name") + "</i><br/>" +
                                            "<strong>SHA256</strong>:     <i>" + nameFile.get("sha256") + "</i><br/>" +
                                            "<strong>Status</strong>:     <i>" + status + "</i><br/>" +
                                            "<strong>Link</strong>: <a href='" + "https://www.virustotal.com/gui/file/" + hashSHA256 + "/detection'>here</a>(may not work when it is 'queued', check out later. The result can't be trusted for now)<br/><br/>";

                            resultTextPane.setText(result);
                            EntityUtils.consume(entity);
                        }else {
                            resultTextPane.setText("GET Request succeed but the result is null (check again get request)");
                        }
                    }else {
                        resultTextPane.setText("GET Request failed (you may check your API)");
                    }
                }else {
                    resultTextPane.setText("POST succeed but the result is null (check post request and your api)");
                }

                //-file > 32MB
            } else {

                //System.out.println("File size exceed 32MB");
                //I need a special URL - GET files/upload_url
                if (alreadyExistGET(3, null)) {
                    try {
                        entity = response.getEntity();
                        if (entity != null) {
                            jsonResultString = EntityUtils.toString(entity);
                            jsonResultJSON = (JSONObject) parser.parse(jsonResultString);
                            String myURL = (String) jsonResultJSON.get("data");

                            Map<String, String> paramValue = new HashMap<>();
                            paramValue.put("url", myURL);

                            //then send the POST request to the upload URL instead of sending it to /files.
                            JSONObject obj = setParameterPOST(paramValue);

                            if (obj != null) {
                                JSONObject data = (JSONObject) obj.get("data");
                                String idAnalyse = (String) data.get("id");

                                //I got an ID that i can use on https://www.virustotal.com/api/v3/analyses/ID;
                                if (alreadyExistGET(2, idAnalyse)) {
                                    entity = response.getEntity();
                                    if (entity != null) {
                                        // return it as a String
                                        jsonResultString = EntityUtils.toString(entity);
                                        jsonResultJSON = (JSONObject) parser.parse(jsonResultString);
                                        data = (JSONObject) jsonResultJSON.get("data");
                                        JSONObject attributes = (JSONObject) data.get("attributes");
                                        JSONObject stats = (JSONObject) attributes.get("stats");
                                        String status = (String) attributes.get("status");

                                        String result =
                                                "<strong>Malicious</strong>:  <i>" + stats.get("malicious") + "</i><br/>" +
                                                        "<strong>Undetected</strong>: <i>" + stats.get("undetected") + "</i><br/>" +
                                                        "<strong>Suspicious</strong>: <i>" + stats.get("suspicious") + "</i><br/>" +
                                                        "<strong>Status</strong>: <i>" + status + "</i><br/>" +
                                                        "<strong>Link</strong>: <a href='" + "https://www.virustotal.com/gui/file/" + hashSHA256 + "/detection'>here</a> (may not work when it is 'queued', check out later. The result can't be trusted for now)<br/><br/>";

                                        resultTextPane.setText(result);
                                    }else {
                                        resultTextPane.setText("GET Request succeed but the result is null");
                                    }
                                }else {
                                    resultTextPane.setText("GET Request failed (analyses/ID)");
                                }
                            }else {
                                resultTextPane.setText("An error occured during the POST Request");
                            }

                        }else {
                            resultTextPane.setText("GET Request failed ");
                        }
                    } catch (Exception e) {

                    }
                } else {
                    resultTextPane.setText("GET Request failed (you may check your API)");
                }

            }
        }

    }

    private void setVariables(String url) {
        String[] splitURL = url.split("&");
        String[] removeFromURL = {"apikey=", "hash=", "path="};
        int k = 0;

        for(String str : splitURL) {
            for(String str2 : removeFromURL) {
                if(str.contains(str2)) {
                    splitURL[k] = str.replace(str2, "");
                }
            }
            k++;
        }

        apiKey = splitURL[0];
        hashSHA256 = splitURL[1];
        //try it out
        //hashSHA256 = "35cf775efe9f4cfb8413f324694f4d9fadea496611de583f2c4da7bc00201208";
        filePath = splitURL[2];
        currentFile = new File(splitURL[2]);

        filesURL = "https://www.virustotal.com/api/v3/files/";
        filesUrlPOST= "https://www.virustotal.com/api/v3/files";
        urlAnalyseID = "https://www.virustotal.com/api/v3/analyses/";
        uploadURL = "https://www.virustotal.com/api/v3/files/upload_url";
        postURL = "https://www.virustotal.com/api/v3/urls";

        parser = new JSONParser();
    }

    //file object to check accordingly to sizeLimit param
    private boolean checkFileSize(File file, int sizeLimit) {
        // Get length of file in bytes
        long fileSizeInBytes = file.length();
        // Convert the bytes to Kilobytes (1 KB = 1024 Bytes)
        long fileSizeInKB = fileSizeInBytes / 1024;
        // Convert the KB to MegaBytes (1 MB = 1024 KBytes)
        long fileSizeInMB = fileSizeInKB / 1024;

        return (fileSizeInMB <= sizeLimit) ? true:false;
    }

    //https://developers.virustotal.com/v3.0/reference#file-info
    //GET - https://www.virustotal.com/api/v3/files/id
    /*
        curl --request GET \
          --url https://www.virustotal.com/api/v3/files/{id} \
          --header 'x-apikey: <your API key>'
     */
    private boolean alreadyExistGET(int i, String id) throws IOException {
        String myURL = "";
        switch(i) {
                //https://www.virustotal.com/api/v3/files/hashSHA256
            case 1:
                //System.out.println("case1");
                myURL = filesURL + hashSHA256;
                break;
                //https://www.virustotal.com/api/v3/analyses/ID;
            case 2:
                //System.out.println("case2");
                myURL = urlAnalyseID + id;
                break;
                //https://www.virustotal.com/api/v3/files/upload_url
            case 3:
                //System.out.println("case3");
                myURL = uploadURL;
                break;
            default:
                break;
        }
        httpclient = HttpClients.createDefault();
        requestHTTPGet = new HttpGet(myURL);
        //For authenticating with the API you must include the x-apikey header with your personal API key in all your requests.
        requestHTTPGet.addHeader("x-apikey", apiKey);

        response = httpclient.execute(requestHTTPGet);
        int statusCode = 0;

        try {
            statusCode = response.getStatusLine().getStatusCode();
            //System.out.println(statusCode);

        } catch (Exception e) {
            return false;
        }

        return (statusCode == 200) ? true:false;
    }

    private JSONObject uploadFilePOST() {
        //https://www.virustotal.com/api/v3/files
        requestHTTPPost = new HttpPost(filesUrlPOST);
        requestHTTPPost.addHeader("x-apikey", apiKey);
        HttpEntity entity = MultipartEntityBuilder.create().addPart("file", new FileBody(currentFile)).build();
        requestHTTPPost.setEntity(entity);

        try (CloseableHttpClient httpClient = HttpClients.createDefault();
             CloseableHttpResponse response = httpClient.execute(requestHTTPPost)) {
            String result = EntityUtils.toString(response.getEntity());
            jsonResultJSON = (JSONObject) parser.parse(result);
            return jsonResultJSON;
        } catch (ParseException | IOException e) {
            e.printStackTrace();
        }
        resultTextPane.setText("An error occured while trying to upload the file");

        return null;
    }
    private JSONObject setParameterPOST(Map<String, String> paramMap) throws IOException {
        requestHTTPPost = new HttpPost(postURL);
        List <NameValuePair> nvps = new ArrayList <NameValuePair>();

        for (Map.Entry<String, String> entry : paramMap.entrySet()) {
            String key = entry.getKey();
            String value = entry.getValue();

            nvps.add(new BasicNameValuePair(key, value));
        }

        requestHTTPPost.setEntity(new UrlEncodedFormEntity(nvps));
        requestHTTPPost.addHeader("x-apikey", apiKey);
        response = httpclient.execute(requestHTTPPost);

        String result = "";
        int statusCode = response.getStatusLine().getStatusCode();
        try {
            if(statusCode==200) {
                entity = response.getEntity();

                // return it as a String
                result = EntityUtils.toString(entity);
                //System.out.println(result);
                jsonResultJSON = (JSONObject) parser.parse(result);
            }
        } catch (ParseException e) {
            e.printStackTrace();
        } finally {
            response.close();
        }

        if(statusCode==200) {
            return jsonResultJSON;
        }else {
            return null;
        }
    }

    public static void openURI(String url) {
        if(!java.awt.Desktop.isDesktopSupported()) {
            System.err.println( "Desktop is not supported (fatal)" );
            System.exit( 1 );
        }

        java.awt.Desktop desktop = java.awt.Desktop.getDesktop();
        if(!desktop.isSupported( java.awt.Desktop.Action.BROWSE )) {
            System.err.println( "Desktop doesn't support the browse action (fatal)" );
            System.exit( 1 );
        }

        try {
            java.net.URI uri = new java.net.URI(url);
            desktop.browse(uri);
        }
        catch (Exception e) {
            System.err.println(e.getMessage());
        }
    }


}
