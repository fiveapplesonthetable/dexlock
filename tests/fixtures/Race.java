package t;
public class Race {
    int mX;                              // guarded by mLock in most places, not all
    final Object mLock = new Object();
    void set(int v) { synchronized (mLock) { mX = v; } }   // guarded write
    int getLocked() { synchronized (mLock) { return mX; } } // guarded read
    int peek() { return mX; }                               // UNGUARDED read -> race
}
