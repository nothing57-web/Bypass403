package bypass403.context;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.contextmenu.*;
import burp.api.montoya.http.message.HttpRequestResponse;
import bypass403.scanner.BypassScanner;
import javax.swing.*;
import java.awt.Component;
import java.util.List;

public class BypassContextMenuProvider implements ContextMenuItemsProvider {
    private final BypassScanner scanner;

    public BypassContextMenuProvider(MontoyaApi api, BypassScanner scanner) {
        this.scanner = scanner;
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        JMenuItem item = new JMenuItem("Send to Bypass403 Scanner");
        item.addActionListener(e -> {
            for (HttpRequestResponse rr : event.selectedRequestResponses()) {
                scanner.scan(rr.request());
            }
        });
        return List.of(item);
    }
}
