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
    }
}
