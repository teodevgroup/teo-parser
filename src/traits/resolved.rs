use std::cell::RefCell;

pub trait Resolve<T> {

    fn resolved_ref_cell(&self) -> &RefCell<Option<T>>;

    fn resolve(&self, resolved: T) {
        *(unsafe { &mut *self.resolved_ref_cell().as_ptr() }) = Some(resolved);
    }

    fn resolved(&self) -> &T {
        (unsafe { &*self.resolved_ref_cell().as_ptr() }).as_ref().unwrap()
    }

    fn resolved_mut(&self) -> &mut T {
        (unsafe { &mut *self.resolved_ref_cell().as_ptr() }).as_mut().unwrap()
    }

    fn is_resolved(&self) -> bool {
        self.resolved_ref_cell().borrow().is_some()
    }
}

pub trait ResolveAndClone<T>: Resolve<T> where T: Clone {
    fn resolve_and_return(&self, resolved: T) -> T {
        self.resolve(resolved.clone());
        resolved
    }
}