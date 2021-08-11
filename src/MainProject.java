import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import javax.swing.*;
import javax.swing.event.HyperlinkEvent;
import javax.swing.event.HyperlinkListener;
import javax.swing.plaf.ColorUIResource;
import javax.swing.text.*;
import java.awt.*;
import java.awt.datatransfer.*;
import java.awt.dnd.DnDConstants;
import java.awt.dnd.DropTarget;
import java.awt.dnd.DropTargetDropEvent;
import java.awt.event.*;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;

public class MainProject extends JFrame implements ActionListener {
    private JPanel contentPanel;
    private JPanel dAndDPanel;
    private JPanel buttonsPanel;
    private JPanel resultPanel;

    private JTextField apiKeyTextField;
    private JButton resetButton;

    private String[] hashTypeComboChoice = {"md5", "sha1", "sha256"};
    private JComboBox hashTypeComboBox = new JComboBox(hashTypeComboChoice);


    private JScrollPane resultScrollPane;
    private JTextPane resultTextPane;

    private JTextPane dAndDTextPane;

    private java.util.List<File> droppedFiles;

    private String vtApiKey;
    Clipboard clipboard;

    public MainProject() {
        contentPanel = new JPanel();
        dAndDPanel = new JPanel();
        buttonsPanel = new JPanel();
        resultPanel = new JPanel();

        apiKeyTextField = new JTextField();
        resetButton = new JButton("RESET");

        resultScrollPane = new JScrollPane();
        resultTextPane = new JTextPane();
        resultTextPane.setEditable(false);
        resultTextPane.setContentType("text/html");

        DefaultCaret caret = (DefaultCaret) resultTextPane.getCaret();
        caret.setUpdatePolicy(DefaultCaret.NEVER_UPDATE);

        dAndDTextPane = new JTextPane();

        try {
            dAndDTextPane.setEditorKit(new MyEditorKit());
            SimpleAttributeSet attrs = new SimpleAttributeSet();
            StyleConstants.setAlignment(attrs, StyleConstants.ALIGN_CENTER);
            StyledDocument doc = (StyledDocument) dAndDTextPane.getDocument();
            Style fontSize;
            fontSize = doc.addStyle("fontSize", null);
            StyleConstants.setFontSize(fontSize, 30);
            doc.insertString(0, "DRAG AND DROP YOUR FILES HERE", attrs);

            doc.setCharacterAttributes(0, doc.getLength(), fontSize, false);
            doc.setParagraphAttributes(0, doc.getLength() - 1, attrs, false);
        } catch (Exception ex) {
            ex.printStackTrace();
        }

        createAndShowGUI();
    }

    public void createAndShowGUI() {
        droppedFiles = new ArrayList<>();

        dAndDPanel.add(dAndDTextPane);
        dAndDPanel.setPreferredSize(new Dimension(400, 300));
        dAndDTextPane.setPreferredSize(new Dimension(400, 300));
        dAndDTextPane.setEditable(false);

        hashTypeComboBox.setPreferredSize(new Dimension(150, 50));
        apiKeyTextField.setPreferredSize(new Dimension(150, 50));
        resetButton.setPreferredSize(new Dimension(150, 50));

        buttonsPanel.setPreferredSize(new Dimension(590, 60));
        buttonsPanel.add(apiKeyTextField);
        buttonsPanel.add(hashTypeComboBox);
        buttonsPanel.add(resetButton);

        resultScrollPane.setViewportView(resultTextPane);
        resultScrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_ALWAYS);
        resultScrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);
        resultScrollPane.setPreferredSize(new Dimension(500, 500));
        resultScrollPane.setViewportView(resultTextPane);//replace the add

        resultPanel.add(resultScrollPane);

        resetButton.addActionListener(this);
        resetButton.setActionCommand("reset");

        contentPanel.add(dAndDPanel, BorderLayout.NORTH);
        contentPanel.add(buttonsPanel, BorderLayout.CENTER);
        contentPanel.add(resultScrollPane, BorderLayout.SOUTH);

        add(contentPanel);
        //https://stackoverflow.com/questions/34778965/how-to-remove-auto-focus-in-swing
        getContentPane().requestFocusInWindow(); //leave the default focus to the JFrame
        setTitle("Hash and VirusTotal Checker");
        setVisible(true);//making the frame visible
        setResizable(false);//not resizable, fixed
        setSize(600, 1000);
        setLocationRelativeTo(null);//center


        //Change JTextPane backGround on Nimbus style
        Color bgColor = Color.WHITE;
        UIDefaults defaults = new UIDefaults();
        defaults.put("TextPane.background", new ColorUIResource(bgColor));
        defaults.put("TextPane[Enabled].backgroundPainter", bgColor);
        dAndDTextPane.putClientProperty("Nimbus.Overrides", defaults);
        dAndDTextPane.putClientProperty("Nimbus.Overrides.InheritDefaults", true);
        dAndDTextPane.setBackground(bgColor);

        Font newTextFieldFont = new Font(apiKeyTextField.getFont().getName(), Font.ITALIC + Font.BOLD, apiKeyTextField.getFont().getSize());
        apiKeyTextField.setFont(newTextFieldFont);
        apiKeyTextField.setText("Type your VT API Key...");
        apiKeyTextField.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                apiKeyTextField.setText("");
            }
        });


        dAndDTextPane.setDropTarget(new DropTarget() {
            public synchronized void drop(DropTargetDropEvent evt) {
                String str = apiKeyTextField.getText();
                if (!str.equals("Type your VT API Key...") && !str.equals("")) {
                    try {
                        evt.acceptDrop(DnDConstants.ACTION_COPY);
                        boolean isHere = false;

                        for (File f1 : (java.util.List<File>) evt.getTransferable().getTransferData(DataFlavor.javaFileListFlavor)) {
                            String fileName1 = f1.getName();

                            for (File f2 : droppedFiles) {
                                String fileName2 = f2.getName();

                                if (fileName1.equals(fileName2)) {
                                    isHere = true;
                                }
                            }
                            if (!isHere) {
                                droppedFiles.add(f1);
                            }

                        }
                        updateResultTextPane();

                    } catch (Exception ex) {
                        ex.printStackTrace();
                    }
                } else {
                    try {
                        evt.acceptDrop(DnDConstants.ACTION_COPY);
                        String res = "";
                        for (File f1 : (java.util.List<File>) evt.getTransferable().getTransferData(DataFlavor.javaFileListFlavor)) {
                            res += "<strong>File name</strong>: " + f1.getName() + " <br/>" +
                                    "<i><a href='" + f1.getAbsolutePath() + "'>Hash (clipboard)</a></i> <br/>";
                            resultTextPane.setText(res);
                        }
                    } catch (UnsupportedFlavorException e) {
                        e.printStackTrace();
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }
            }
        });

        resultTextPane.addHyperlinkListener(new HyperlinkListener() {
            @Override
            public void hyperlinkUpdate(HyperlinkEvent e) {
                if (e.getEventType() == HyperlinkEvent.EventType.ACTIVATED) {

                    if (e.getDescription().contains("apikey=")) {
                        try {
                            AnalyseGUI analyseGUI = new AnalyseGUI(e.getDescription());
                            //setVisible(false);
                        } catch (IOException | ParseException ioException) {
                            ioException.printStackTrace();
                        }
                    } else if (e.getURL() != null) {
                        AnalyseGUI.openURI(e.getURL().toString());
                    } else {
                        if(droppedFiles.isEmpty()) {
                            System.out.println("11");
                            File file = new File(e.getDescription());
                            StringSelection selection = new StringSelection(sumHash(hashTypeComboBox.getSelectedItem().toString(), file));
                            clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
                            clipboard.setContents(selection, selection);
                        }

                        for (File file : droppedFiles) {
                            if (file.getName().equals(e.getDescription())) {
                                StringSelection selection = new StringSelection(sumHash(hashTypeComboBox.getSelectedItem().toString(), file));
                                clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
                                clipboard.setContents(selection, selection);
                            }
                        }
                    }
                }
            }
        }
    );

    addWindowListener(new WindowAdapter() {
        public void windowClosing (WindowEvent e){
            System.exit(0);
        }
    });
}

    @Override
    public void actionPerformed(ActionEvent e) {
        String actionName = e.getActionCommand();

        if (actionName.equals("reset")) {
            reset();
        }
    }

    private void reset() {
        droppedFiles.clear();
        hashTypeComboBox.setSelectedIndex(0);
        resultTextPane.setText("");
        StringSelection stringSelection = new StringSelection("");
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(stringSelection, null);
    }

    public String sumHash(String hashType, File f) {
        String result = "";

        try (InputStream is = Files.newInputStream(Paths.get(f.getPath()))) {
            switch (hashType) {
                case "md5":
                    String md5 = org.apache.commons.codec.digest.DigestUtils.md5Hex(is);
                    result = md5;
                    break;

                case "sha1":
                    String sha1 = org.apache.commons.codec.digest.DigestUtils.sha1Hex(is);
                    result = sha1;
                    break;
                case "sha256":
                    String sha256 = org.apache.commons.codec.digest.DigestUtils.sha256Hex(is);
                    result = sha256;
                    break;
                default:
                    break;
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        return result;
    }

    public void updateResultTextPane() throws UnsupportedEncodingException {
        String str = "";
        if (droppedFiles.isEmpty()) {
            resultTextPane.setText("");
        } else {

            for (File file : droppedFiles) {
                //https://developers.virustotal.com/reference#file-report
                String urlStr = String.format("apikey=%s&hash=%s&path=%s", apiKeyTextField.getText(), sumHash("sha256", file), file.getAbsolutePath());
                str += "<strong>File name</strong>: " + file.getName() + " <br/>" +
                        "<i><a href='" + file.getName() + "'>Hash (clipboard)</a></i> <br/>" +
                        "<i><a href='" + urlStr + "'>VirusTotal Scratch Check</a></i><br/><br/>";
            }

            resultTextPane.setText("The Public API is limited to 500 requests per day and a rate of 4 requests per minute.<br/>" +
                    "If you change your API Key after you droped the file, use reset to get the right API<br/>" +
                    "More information about the API there : <a href='https://developers.virustotal.com/v3.0/reference#overview'>here</a> <br/><br/>" +
                    str);
        }
    }

    //not used
    public String getFromURL(String url, String matchValue) {
        String[] splitURL = url.split("&");

        for (String str : splitURL) {
            if (str.contains(matchValue)) {
                return str.replace(matchValue, "");
            }
        }
        return "";
    }
}
