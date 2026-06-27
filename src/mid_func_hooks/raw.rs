use crate::arch::MidFuncHook;

use crate::error::Result;

#[derive(Debug)]
pub struct RawMidFuncHook(MidFuncHook);

// TODO: stop all threads in target during patch?
impl RawMidFuncHook {
  /// Constructs a new mid-function hook.
  ///
  /// The hook is disabled by default.
  pub unsafe fn new(target: *const (), hook: *const (), original_first: bool) -> Result<Self> {
    MidFuncHook::new(target, hook, original_first).map(RawMidFuncHook)
  }

  /// Enables the hook.
  pub unsafe fn enable(&self) -> Result<()> {
    self.0.enable()
  }

  /// Disables the hook.
  pub unsafe fn disable(&self) -> Result<()> {
    self.0.disable()
  }

  /// Returns whether the hook is enabled or not.
  pub fn is_enabled(&self) -> bool {
    self.0.is_enabled()
  }
}

unsafe impl Send for RawMidFuncHook {}
unsafe impl Sync for RawMidFuncHook {}
