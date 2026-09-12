// Fixture for the binder-under-lock pass. Compiled to binder.dex (committed).
//
// A minimal AIDL surface: our own `android.os.IInterface` (the marker the pass keys
// on) and `IFoo` extending it. `Holder` makes an invoke-interface call to `IFoo`
// while holding `mLock` (a positive: binder call under lock), the same call with no
// lock held (a negative), and a call to a plain non-binder helper under the lock
// (a negative: only interface-dispatched AIDL calls count).
//
// Rebuild binder.dex (needs two-line stubs for the android.os marker types the pass
// keys on — `IInterface { IBinder asBinder(); }` and an empty `IBinder`):
//   javac -d out Binder.java android/os/IInterface.java android/os/IBinder.java
//   d8 --min-api 21 --output out $(find out -name '*.class') && cp out/classes.dex binder.dex
package t;

class Binder {
    interface IFoo extends android.os.IInterface {
        void doRemote();
    }

    static class Holder {
        private final Object mLock = new Object();
        private IFoo mFoo;

        // POSITIVE: interface-dispatched binder call while holding mLock.
        void underLock() {
            synchronized (mLock) {
                mFoo.doRemote();
            }
        }

        // POSITIVE: a synchronized *method* (d8/R8 lower it to an explicit
        // monitor-enter over the body, so `this` is held across the call).
        synchronized void underSyncMethod() {
            mFoo.doRemote();
        }

        // NEGATIVE: same binder call, no lock held.
        void noLock() {
            mFoo.doRemote();
        }

        // NEGATIVE: a plain (non-binder) helper called under the lock.
        void helperUnderLock() {
            synchronized (mLock) {
                plain();
            }
        }

        private void plain() {}

        // POSITIVE (interprocedural): the binder call is in a private helper whose
        // sole caller holds mLock, so the lock is one frame up. entry_held infers
        // mLock on entry to helperLocked and the call is flagged there.
        void callsHelper() {
            synchronized (mLock) {
                helperLocked();
            }
        }

        private void helperLocked() {
            mFoo.doRemote();
        }
    }
}
