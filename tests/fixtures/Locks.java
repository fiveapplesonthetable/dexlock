package t;
public class Locks {
    final Object mLock = new Object();
    static final Object sLock = new Object();
    void a() { synchronized (mLock) { work(); } }        // -> t.Locks.mLock
    void b() { synchronized (sLock) { work(); } }        // -> t.Locks.sLock
    synchronized void c() { work(); }                    // synchronized method -> this (t.Locks)
    static synchronized void d() { work(); }             // static synchronized -> t.Locks.class
    static void work() {}
}
