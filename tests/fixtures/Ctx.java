// Fixture for the lock-context index (ctx). Compiled to ctx.dex (committed).
//
// top() takes mA and calls mid(), which calls leaf(): mA may be held on entry to
// leaf, with witness path top -> mid -> leaf. nested() takes mA under mB and
// other() takes mB under mA, so the lock-order graph has the cycle {mA, mB}.
// Rebuild: javac -d out Ctx.java && d8 --min-api 21 --output out out/t/*.class && cp out/classes.dex ctx.dex
package t;

class Ctx {
    final Object mA = new Object();
    final Object mB = new Object();
    void top() { synchronized (mA) { mid(); } }
    void mid() { leaf(); }
    void leaf() { }
    void nested() { synchronized (mB) { synchronized (mA) { } } }
    void other() { synchronized (mA) { synchronized (mB) { } } }
}
