// Copyright (C) 2026 The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Recognition of `java.util.concurrent.locks` operations by (class, method).
//! Monitor enter/exit come from dex `monitor-*` instructions; these are ordinary
//! method calls the extractor translates into the same lock effects.

/// What an invoke means for lock resolution, if anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockCall {
    /// `Lock.lock()` / `lockInterruptibly()` — acquire of the receiver.
    Acquire,
    /// `Lock.tryLock()` — non-blocking acquire.
    TryAcquire,
    /// `Lock.unlock()` — release of the receiver.
    Release,
    /// `ReadWriteLock.readLock()` — returns the receiver tagged read-mode.
    ReadView,
    /// `ReadWriteLock.writeLock()` — returns the receiver tagged write-mode.
    WriteView,
}

/// A lock type, matched by simple-name suffix so the exact package is irrelevant.
fn is_lock_type(class: &str) -> bool {
    let c = class.rsplit('.').next().unwrap_or(class);
    matches!(c, "Lock" | "ReentrantLock" | "ReentrantReadWriteLock" | "ReadLock" | "WriteLock")
        || class.contains("locks.")
}

pub fn classify(class: &str, name: &str) -> Option<LockCall> {
    if name == "readLock" {
        return Some(LockCall::ReadView);
    }
    if name == "writeLock" {
        return Some(LockCall::WriteView);
    }
    if is_lock_type(class) {
        return match name {
            "lock" | "lockInterruptibly" | "acquire" | "acquireUninterruptibly" => {
                Some(LockCall::Acquire)
            }
            "tryLock" | "tryAcquire" => Some(LockCall::TryAcquire),
            "unlock" | "release" => Some(LockCall::Release),
            _ => None,
        };
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_lock_operations() {
        let rl = "java.util.concurrent.locks.ReentrantLock";
        assert_eq!(classify(rl, "lock"), Some(LockCall::Acquire));
        assert_eq!(classify(rl, "lockInterruptibly"), Some(LockCall::Acquire));
        assert_eq!(classify(rl, "tryLock"), Some(LockCall::TryAcquire));
        assert_eq!(classify(rl, "unlock"), Some(LockCall::Release));
        let rw = "java.util.concurrent.locks.ReentrantReadWriteLock";
        assert_eq!(classify(rw, "readLock"), Some(LockCall::ReadView));
        assert_eq!(classify(rw, "writeLock"), Some(LockCall::WriteView));
    }

    #[test]
    fn ignores_non_lock_calls() {
        assert_eq!(classify("com.example.Widget", "lock"), None);
        assert_eq!(classify("com.example.Widget", "doWork"), None);
    }
}
