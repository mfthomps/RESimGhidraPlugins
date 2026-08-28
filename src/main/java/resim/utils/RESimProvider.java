package resim.utils;

import java.util.concurrent.CompletableFuture;

public interface RESimProvider {
    public CompletableFuture<Void> refresh();
}
