package bypass403.ui;

import burp.api.montoya.MontoyaApi;
import bypass403.config.Config;
import bypass403.config.ConfigManager;
import bypass403.model.BypassResult;
import bypass403.scanner.BypassScanner;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;

public class Bypass403Panel extends JPanel {
    private final MontoyaApi api;
    private final BypassScanner scanner;
    private final ConfigManager configManager;
    private final ResultsTableModel resultsModel = new ResultsTableModel();
    private final JTable table = new JTable(resultsModel);

    private final JCheckBox path = check("Path manipulation", true);
    private final JCheckBox methods = check("HTTP methods", true);
    private final JCheckBox headers = check("Header injection", true);
    private final JCheckBox combinations = check("Path + header", true);
    private final JCheckBox bodies = check("Body manipulation", true);
    private final JCheckBox fuzz = check("Trailing/leading fuzzing", true);
    private final JCheckBox dangerous = check("Enable OPTIONS/TRACE", false);
    private final JTextField customName = new JTextField();
    private final JTextField customValue = new JTextField();
    private final JSpinner maxPayloads = spinner(200, 1, 2000);
    private final JSpinner threads = spinner(5, 1, 20);
    private final JSpinner delay = spinner(100, 0, 60000);
    private final JSpinner rate = spinner(10, 1, 1000);

    public Bypass403Panel(MontoyaApi api) {
        super(new BorderLayout());
        this.api = api;
        this.scanner = new BypassScanner(api);
        this.configManager = new ConfigManager(api);
        scanner.setResultConsumer(this::addResult);

        JLabel warning = new JLabel("  ⚠ For authorized testing only — scope is enforced; OPTIONS/TRACE are disabled by default  ");
        warning.setOpaque(true);
        warning.setBackground(new Color(255, 210, 70));
        warning.setForeground(Color.BLACK);
        warning.setFont(warning.getFont().deriveFont(Font.BOLD));
        warning.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));
        add(warning, BorderLayout.NORTH);

        JPanel config = buildConfigPanel();
        JPanel bottom = new JPanel(new BorderLayout());
        bottom.setBorder(BorderFactory.createTitledBorder("Results"));
        table.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
        table.getColumnModel().getColumn(0).setPreferredWidth(260);
        table.getColumnModel().getColumn(1).setPreferredWidth(180);
        table.getColumnModel().getColumn(2).setPreferredWidth(260);
        table.getColumnModel().getColumn(6).setPreferredWidth(100);
        table.setDefaultRenderer(Object.class, new ResultRenderer(resultsModel));
        table.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override public void mouseClicked(java.awt.event.MouseEvent event) {
                if (event.getClickCount() == 2) {
                    int row = table.getSelectedRow();
                    if (row >= 0) {
                        BypassResult result = resultsModel.get(row);
                        api.repeater().sendToRepeater(result.request(), "Bypass403 " + result.status());
                    }
                }
            }
        });
        bottom.add(new JScrollPane(table), BorderLayout.CENTER);

        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, new JScrollPane(config), bottom);
        split.setResizeWeight(0.28);
        add(split, BorderLayout.CENTER);

        restoreConfig();
        SwingUtilities.invokeLater(this::applyConfig);
    }

    public BypassScanner getScanner() { return scanner; }

    private JPanel buildConfigPanel() {
        JPanel config = new JPanel(new GridBagLayout());
        config.setBorder(BorderFactory.createTitledBorder("Configuration"));
        GridBagConstraints c = new GridBagConstraints();
        c.insets = new Insets(3, 5, 3, 5); c.anchor = GridBagConstraints.WEST;

        c.gridx = 0; c.gridy = 0; config.add(path, c);
        c.gridx = 1; config.add(methods, c);
        c.gridx = 2; config.add(headers, c);
        c.gridx = 3; config.add(combinations, c);
        c.gridx = 0; c.gridy = 1; config.add(bodies, c);
        c.gridx = 1; config.add(fuzz, c);
        c.gridx = 2; config.add(dangerous, c);
        c.gridx = 0; c.gridy = 2; config.add(new JLabel("Custom header name"), c);
        c.gridx = 1; config.add(customName, c);
        c.gridx = 2; config.add(new JLabel("Custom header value"), c);
        c.gridx = 3; config.add(customValue, c);
        c.gridx = 0; c.gridy = 3; config.add(new JLabel("Max payloads"), c);
        c.gridx = 1; config.add(maxPayloads, c);
        c.gridx = 2; config.add(new JLabel("Threads"), c);
        c.gridx = 3; config.add(threads, c);
        c.gridx = 0; c.gridy = 4; config.add(new JLabel("Delay (ms)"), c);
        c.gridx = 1; config.add(delay, c);
        c.gridx = 2; config.add(new JLabel("Requests/sec"), c);
        c.gridx = 3; config.add(rate, c);

        JButton clear = new JButton("Clear Results");
        clear.addActionListener(e -> {
            resultsModel.clear();
            scanner.clearResults();
        });
        JButton apply = new JButton("Apply & Save");
        apply.addActionListener(e -> applyConfig());
        c.gridx = 0; c.gridy = 5; c.gridwidth = 2; config.add(clear, c);
        c.gridx = 2; config.add(apply, c);
        return config;
    }

    private void applyConfig() {
        Config config = readConfig();
        scanner.configure(config);
        configManager.save(config);
        api.logging().logToOutput("Bypass403 configuration applied and saved");
    }

    private Config readConfig() {
        return new Config((Integer) maxPayloads.getValue(), (Integer) threads.getValue(),
            (Integer) delay.getValue(), (Integer) rate.getValue(), path.isSelected(), methods.isSelected(),
            headers.isSelected(), combinations.isSelected(), bodies.isSelected(), fuzz.isSelected(),
            dangerous.isSelected(), customName.getText(), customValue.getText()).sanitized();
    }

    private void restoreConfig() {
        Config c = configManager.load();
        maxPayloads.setValue(c.maxPayloads()); threads.setValue(c.threadCount());
        delay.setValue(c.delayMs()); rate.setValue(c.requestsPerSecond());
        path.setSelected(c.pathEnabled()); methods.setSelected(c.methodEnabled());
        headers.setSelected(c.headerEnabled()); combinations.setSelected(c.combinationEnabled());
        bodies.setSelected(c.bodyEnabled()); fuzz.setSelected(c.fuzzEnabled());
        dangerous.setSelected(c.dangerousMethodsEnabled()); customName.setText(c.customHeaderName());
        customValue.setText(c.customHeaderValue());
    }

    private void addResult(BypassResult result) {
        SwingUtilities.invokeLater(() -> resultsModel.add(result));
    }

    private JCheckBox check(String name, boolean selected) { return new JCheckBox(name, selected); }
    private JSpinner spinner(int value, int min, int max) { return new JSpinner(new SpinnerNumberModel(value, min, max, 1)); }

    public static class ResultsTableModel extends AbstractTableModel {
        private final String[] columns = {"Original URL", "Technique", "Payload", "Status", "Length", "Time", "Action"};
        private final List<BypassResult> rows = new ArrayList<>();

        public synchronized void add(BypassResult result) {
            int row = rows.size(); rows.add(result); fireTableRowsInserted(row, row);
        }
        public synchronized void clear() { int size = rows.size(); rows.clear(); if (size > 0) fireTableRowsDeleted(0, size - 1); }
        public synchronized BypassResult get(int row) { return rows.get(row); }
        @Override public synchronized int getRowCount() { return rows.size(); }
        @Override public int getColumnCount() { return columns.length; }
        @Override public String getColumnName(int column) { return columns[column]; }
        @Override public synchronized Object getValueAt(int row, int column) {
            BypassResult r = rows.get(row);
            return switch (column) { case 0 -> r.originalUrl(); case 1 -> r.technique(); case 2 -> r.request().toString(); case 3 -> r.status(); case 4 -> r.length(); case 5 -> r.timeMs() + " ms"; case 6 -> "Send"; default -> ""; };
        }
        @Override public Class<?> getColumnClass(int column) { return column == 3 || column == 4 ? Integer.class : String.class; }
        @Override public boolean isCellEditable(int row, int column) { return false; }
    }

    private static class ResultRenderer extends DefaultTableCellRenderer {
        private final ResultsTableModel model;
        ResultRenderer(ResultsTableModel model) { this.model = model; }
        @Override public Component getTableCellRendererComponent(JTable table, Object value, boolean selected, boolean focus, int row, int column) {
            Component c = super.getTableCellRendererComponent(table, value, selected, focus, row, column);
            if (!selected) {
                BypassResult r = model.get(row);
                c.setBackground(r.status() == 0 ? Color.LIGHT_GRAY : r.succeeded() ? new Color(210, 255, 210) : r.status() == 403 ? new Color(255, 210, 210) : Color.LIGHT_GRAY);
            }
            return c;
        }
    }
}
