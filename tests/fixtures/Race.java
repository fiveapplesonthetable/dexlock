// Fixture for the inconsistent-locking pass. Compiled to race.dex (committed).
//
// Rebuild: javac -d out Race.java && d8 --lib android.jar --min-api 21 --output out out/t/*.class && cp out/classes.dex race.dex
package t;

class Race implements Runnable {
    final Object mLock = new Object();

    int mGuarded;       // 5 accesses under mLock, 1 write with none -> reported
    int mCallerLocked;  // 4 reads under mLock, 1 write in a helper the caller locks
    volatile int mVol;  // same shape as mGuarded, but volatile -> excluded
    int mCtorOnly;      // read under mLock; written only by the constructor
    int mNever;         // never guarded anywhere -> no discipline to be inconsistent with

    Race() {
        mCtorOnly = 1;
    }

    // POSITIVE: the discipline is mLock at five accesses; run() writes with none.
    void g1() { synchronized (mLock) { mGuarded = 1; } }
    void g2() { synchronized (mLock) { mGuarded = 2; } }
    void g3() { synchronized (mLock) { sink(mGuarded); } }
    void g4() { synchronized (mLock) { sink(mGuarded); } }
    void g5() { synchronized (mLock) { sink(mGuarded); } }

    // NEGATIVE, and the regression this pass exists to not repeat: the write is in a
    // private helper whose every caller holds mLock, so the lock is one frame up.
    // Counted as unguarded it would clear both thresholds and be reported.
    void c1() { synchronized (mLock) { helperLocked(); } }
    void c2() { synchronized (mLock) { sink(mCallerLocked); } }
    void c3() { synchronized (mLock) { sink(mCallerLocked); } }
    void c4() { synchronized (mLock) { sink(mCallerLocked); } }
    void c5() { synchronized (mLock) { sink(mCallerLocked); } }
    private void helperLocked() { mCallerLocked = 1; }

    // NEGATIVE: volatile is lock-free by construction.
    void v1() { synchronized (mLock) { mVol = 1; } }
    void v2() { synchronized (mLock) { sink(mVol); } }
    void v3() { synchronized (mLock) { sink(mVol); } }
    void v4() { synchronized (mLock) { sink(mVol); } }

    // NEGATIVE: the only write is the constructor's, which runs before publication.
    void k1() { synchronized (mLock) { sink(mCtorOnly); } }
    void k2() { synchronized (mLock) { sink(mCtorOnly); } }
    void k3() { synchronized (mLock) { sink(mCtorOnly); } }

    // NEGATIVE: no lock anywhere, so nothing is inconsistent.
    void n1() { mNever = 1; }
    void n2() { sink(mNever); }

    // A concurrent entry point: the unguarded write runs on another thread.
    @Override
    public void run() {
        mGuarded = 9;
        mVol = 9;
    }

    static void sink(int v) {}
}
