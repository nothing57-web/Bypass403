package bypass403.scanner;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class ResponseComparatorTest {
    private final ResponseComparator comparator = new ResponseComparator();

    @Test
    void classifiesStatusAndBodyChanges() {
        assertTrue(comparator.isBypass(new ResponseSnapshot(403, 100, "Forbidden"), new ResponseSnapshot(200, 200, "Admin")));
        assertFalse(comparator.isBypass(new ResponseSnapshot(403, 100, "Forbidden"), new ResponseSnapshot(403, 100, "Forbidden")));
        assertTrue(comparator.isBypass(new ResponseSnapshot(200, 100, "Before"), new ResponseSnapshot(200, 101, "After")));
        assertFalse(comparator.isBypass(new ResponseSnapshot(200, 100, "Identical"), new ResponseSnapshot(200, 100, "Identical")));
    }

    @Test
    void normalizerRemovesDynamicTokensAndTimestamps() {
        String a = "<html>timestamp=1700000000000 csrf=aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee nonce=abc123</html>";
        String b = "<html>timestamp=1700000999999 csrf=11111111-2222-3333-4444-555555555555 nonce=xyz789</html>";
        assertEquals(comparator.normalize(a), comparator.normalize(b));
    }
}
