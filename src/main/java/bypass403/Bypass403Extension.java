package bypass403;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import bypass403.context.BypassContextMenuProvider;
import bypass403.http.BypassHttpHandler;
import bypass403.scanner.BypassScanner;
import bypass403.ui.Bypass403Panel;

public final class Bypass403Extension implements BurpExtension {
    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("Bypass403");
        api.logging().logToOutput("Bypass403 loaded — authorized testing only");

        Bypass403Panel panel = new Bypass403Panel(api);
        BypassScanner scanner = panel.getScanner();

        api.userInterface().registerSuiteTab("Bypass403", panel);
        api.http().registerHttpHandler(new BypassHttpHandler(api, scanner));
        api.userInterface().registerContextMenuItemsProvider(new BypassContextMenuProvider(api, scanner));
        api.extension().registerUnloadingHandler(scanner::shutdown);
    }
}
