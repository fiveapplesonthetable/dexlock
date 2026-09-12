// Fixture for control-flow-aware held-lock tracking. Compiled to cfg.dex (committed).
//
// Each helper call is made in a specific lock context; the test asserts the locks
// held at each call site. Early return, a catch handler, try/finally, a switch, a
// loop, a successful tryLock, a read-write lock view, and a lock taken and released
// through helper methods all appear.
// Rebuild: javac -d out Cfg.java && d8 --min-api 21 --output out out/t/*.class && cp out/classes.dex cfg.dex
package t;

import java.util.concurrent.locks.ReentrantLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

class Cfg {
    final Object mA = new Object();
    final ReentrantLock mL = new ReentrantLock();
    final ReentrantReadWriteLock mRw = new ReentrantReadWriteLock();

    void early(boolean c) {
        synchronized (mA) {
            if (c) {
                return;
            }
            after();          // still inside the block: mA held
        }
        outside();            // mA released
    }

    void catches() {
        synchronized (mA) {
            try {
                risky();
            } catch (RuntimeException e) {
                inCatch();    // handler runs with mA held
            }
        }
    }

    void fin() {
        synchronized (mA) {
            try {
                risky();
            } finally {
                inFinally();  // mA held
            }
        }
    }

    void switchy(int k) {
        synchronized (mA) {
            switch (k) {
                case 1: s1(); break;
                case 2: s2(); break;
                default: s3();
            }
        }
    }

    void loop(int n) {
        for (int i = 0; i < n; i++) {
            synchronized (mA) {
                body();
            }
        }
        tail();               // not held
    }

    void tryLock() {
        if (mL.tryLock()) {
            try {
                inTry();      // mL held
            } finally {
                mL.unlock();
            }
        }
        post();               // not held on either path
    }

    void rw() {
        mRw.readLock().lock();
        try {
            inRead();         // mRw (read) held
        } finally {
            mRw.readLock().unlock();
        }
        afterRead();          // released
    }

    void helper() {
        take();               // a helper takes mL and returns holding it
        inHelperLock();       // mL held
        drop();               // a helper releases it
        afterHelper();        // not held
    }

    private void take() { mL.lock(); }
    private void drop() { mL.unlock(); }

    void after() {} void outside() {} void risky() {} void inCatch() {} void inFinally() {}
    void s1() {} void s2() {} void s3() {} void body() {} void tail() {}
    void inTry() {} void post() {} void inRead() {} void afterRead() {}
    void inHelperLock() {} void afterHelper() {}
}
