import javax.swing.*;
import javax.swing.filechooser.FileSystemView;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.logging.Level;
import java.util.logging.Logger;

public class DecryptorView extends JFrame {
    private String inFilePath;

    private String outFilePath;

    private JButton cancelButton;

    private JButton inButton;

    private JTextField inText;

    private JLabel jLabel1;

    private JLabel jLabel2;

    private JLabel jLabel3;

    private JLabel jLabel4;

    private JLabel jLabel5;

    private JLabel jLabel6;

    private JPanel jPanel1;

    private JPanel jPanel2;

    private JPanel jPanel4;

    private JTextField jTextField1;

    private JTextField jTextField2;

    private JButton makeButton;

    public DecryptorView() {
        initComponents();
    }

    private void initComponents() {
        this.jPanel1 = new JPanel();
        this.jPanel2 = new JPanel();
        this.inText = new JTextField();
        this.inButton = new JButton();
        this.jPanel4 = new JPanel();
        this.makeButton = new JButton();
        this.cancelButton = new JButton();
        this.jLabel2 = new JLabel();
        this.jLabel4 = new JLabel();
        this.jTextField1 = new JTextField();
        this.jTextField2 = new JTextField();
        this.jLabel1 = new JLabel();
        this.jLabel3 = new JLabel();
        this.jLabel5 = new JLabel();
        this.jLabel6 = new JLabel();
        setDefaultCloseOperation(3);
        setMinimumSize(new Dimension(600, 230));
        setPreferredSize(new Dimension(600, 230));
        getContentPane().setLayout(new GridBagLayout());
        this.jPanel1.setMinimumSize(new Dimension(267, 200));
        this.jPanel1.setPreferredSize(new Dimension(267, 200));
        this.jPanel1.setLayout(new GridBagLayout());
        this.jPanel2.setMinimumSize(new Dimension(267, 200));
        this.jPanel2.setPreferredSize(new Dimension(267, 200));
        this.jPanel2.setLayout(new GridBagLayout());
        this.inText.setEditable(false);
        this.inText.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent evt) {
                DecryptorView.this.inTextActionPerformed(evt);
            }
        });
        GridBagConstraints gridBagConstraints = new GridBagConstraints();
        gridBagConstraints.gridx = 2;
        gridBagConstraints.gridy = 1;
        gridBagConstraints.fill = 2;
        gridBagConstraints.weightx = 1.0D;
        gridBagConstraints.insets = new Insets(0, 9, 0, 9);
        this.jPanel2.add(this.inText, gridBagConstraints);
        this.inButton.setText("choose file");
        this.inButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent evt) {
                DecryptorView.this.inButtonActionPerformed(evt);
            }
        });
        gridBagConstraints = new GridBagConstraints();
        gridBagConstraints.gridx = 3;
        gridBagConstraints.gridy = 1;
        gridBagConstraints.anchor = 22;
        this.jPanel2.add(this.inButton, gridBagConstraints);
        this.jPanel4.setLayout(new GridBagLayout());
        this.makeButton.setText("ok");
        this.makeButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent evt) {
                DecryptorView.this.makeButtonActionPerformed(evt);
            }
        });
        gridBagConstraints = new GridBagConstraints();
        gridBagConstraints.gridx = 1;
        gridBagConstraints.gridy = 0;
        gridBagConstraints.anchor = 13;
        this.jPanel4.add(this.makeButton, gridBagConstraints);
        this.cancelButton.setText("cancle");
        this.cancelButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent evt) {
                DecryptorView.this.cancelButtonActionPerformed(evt);
            }
        });
        gridBagConstraints = new GridBagConstraints();
        gridBagConstraints.gridx = 2;
        gridBagConstraints.gridy = 0;
        gridBagConstraints.anchor = 13;
        gridBagConstraints.insets = new Insets(0, 9, 0, 0);
        this.jPanel4.add(this.cancelButton, gridBagConstraints);
        gridBagConstraints = new GridBagConstraints();
        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy = 0;
        gridBagConstraints.fill = 2;
        gridBagConstraints.weightx = 1.0D;
        this.jPanel4.add(this.jLabel2, gridBagConstraints);
        gridBagConstraints = new GridBagConstraints();
        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy = 4;
        gridBagConstraints.gridwidth = 4;
        gridBagConstraints.fill = 2;
        gridBagConstraints.anchor = 13;
        gridBagConstraints.weightx = 1.0D;
        gridBagConstraints.insets = new Insets(4, 0, 9, 0);
        this.jPanel2.add(this.jPanel4, gridBagConstraints);
        this.jLabel4.setText("weblogic decrypt");
                gridBagConstraints = new GridBagConstraints();
        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy = 0;
        gridBagConstraints.gridwidth = 4;
        gridBagConstraints.anchor = 21;
        gridBagConstraints.insets = new Insets(0, 9, 4, 0);
        this.jPanel2.add(this.jLabel4, gridBagConstraints);
        gridBagConstraints = new GridBagConstraints();
        gridBagConstraints.gridx = 2;
        gridBagConstraints.gridy = 2;
        gridBagConstraints.gridwidth = 2;
        gridBagConstraints.fill = 2;
        gridBagConstraints.weightx = 1.0D;
        gridBagConstraints.insets = new Insets(4, 9, 0, 0);
        this.jPanel2.add(this.jTextField1, gridBagConstraints);
        gridBagConstraints = new GridBagConstraints();
        gridBagConstraints.gridx = 2;
        gridBagConstraints.gridy = 3;
        gridBagConstraints.gridwidth = 2;
        gridBagConstraints.fill = 2;
        gridBagConstraints.weightx = 1.0D;
        gridBagConstraints.insets = new Insets(4, 9, 9, 0);
        this.jPanel2.add(this.jTextField2, gridBagConstraints);
        this.jLabel1.setText("file");
                gridBagConstraints = new GridBagConstraints();
        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy = 1;
        gridBagConstraints.insets = new Insets(0, 9, 0, 0);
        this.jPanel2.add(this.jLabel1, gridBagConstraints);
        this.jLabel3.setText("cipher");
                gridBagConstraints = new GridBagConstraints();
        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy = 2;
        gridBagConstraints.insets = new Insets(0, 9, 0, 0);
        this.jPanel2.add(this.jLabel3, gridBagConstraints);
        this.jLabel5.setText("result");
                gridBagConstraints = new GridBagConstraints();
        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy = 3;
        gridBagConstraints.insets = new Insets(0, 9, 0, 0);
        this.jPanel2.add(this.jLabel5, gridBagConstraints);
        gridBagConstraints = new GridBagConstraints();
        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy = 5;
        gridBagConstraints.gridwidth = 4;
        gridBagConstraints.fill = 1;
        gridBagConstraints.weightx = 1.0D;
        gridBagConstraints.weighty = 1.0D;
        this.jPanel2.add(this.jLabel6, gridBagConstraints);
        gridBagConstraints = new GridBagConstraints();
        gridBagConstraints.fill = 1;
        gridBagConstraints.weightx = 1.0D;
        gridBagConstraints.weighty = 1.0D;
        gridBagConstraints.insets = new Insets(9, 0, 0, 9);
        this.jPanel1.add(this.jPanel2, gridBagConstraints);
        gridBagConstraints = new GridBagConstraints();
        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy = 0;
        gridBagConstraints.fill = 1;
        gridBagConstraints.anchor = 18;
        gridBagConstraints.weightx = 1.0D;
        gridBagConstraints.weighty = 1.0D;
        getContentPane().add(this.jPanel1, gridBagConstraints);
        pack();
    }

    private void inTextActionPerformed(ActionEvent evt) {}

    private void inButtonActionPerformed(ActionEvent evt) {
        JFileChooser jfc = new JFileChooser() {
            public void approveSelection() {
                if (getSelectedFile() == null) {
                    JOptionPane.showMessageDialog(DecryptorView.this.rootPane, "choose SerializedSystemIni.dat file");
                    return;
                }
                super.approveSelection();
            }
        };
        jfc.setCurrentDirectory(FileSystemView.getFileSystemView().getHomeDirectory());
        jfc.setAcceptAllFileFilterUsed(false);
        int choseFlag = jfc.showOpenDialog(this);
        if (choseFlag == 0) {
            this.inFilePath = jfc.getSelectedFile().getPath();
            this.inText.setText(this.inFilePath);
        }
    }

    private void makeButtonActionPerformed(ActionEvent evt) {
        if (this.inFilePath == null || "".equals(this.inFilePath)) {
            JOptionPane.showMessageDialog(this.rootPane, "choose SerializedSystemIni.dat file");
            return;
        }
        String key = this.jTextField1.getText();
        if (null == key || "".equals(key)) {
            JOptionPane.showMessageDialog(this.rootPane, "input the cipher");
            return;
        }
        this.jTextField2.setText(DecryptorUtilNew.decrypt(this.inFilePath, key));
    }

    private void cancelButtonActionPerformed(ActionEvent evt) {
        System.exit(0);
    }

    public static void main(String[] args) {
        try {
            for (UIManager.LookAndFeelInfo info : UIManager.getInstalledLookAndFeels()) {
                if ("Nimbus".equals(info.getName())) {
                    UIManager.setLookAndFeel(info.getClassName());
                    break;
                }
            }
        } catch (ClassNotFoundException ex) {
            Logger.getLogger(DecryptorView.class.getName()).log(Level.SEVERE, (String)null, ex);
        } catch (InstantiationException ex) {
            Logger.getLogger(DecryptorView.class.getName()).log(Level.SEVERE, (String)null, ex);
        } catch (IllegalAccessException ex) {
            Logger.getLogger(DecryptorView.class.getName()).log(Level.SEVERE, (String)null, ex);
        } catch (UnsupportedLookAndFeelException ex) {
            Logger.getLogger(DecryptorView.class.getName()).log(Level.SEVERE, (String)null, ex);
        }
        EventQueue.invokeLater(new Runnable() {
            DecryptorView view = new DecryptorView();

            public void run() {
                this.view.setLocationRelativeTo((Component)null);
                this.view.setTitle("weblogic decryption");
                this.view.setVisible(true);
            }
        });
    }
}

