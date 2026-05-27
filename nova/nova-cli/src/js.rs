use rquickjs::{Context, Runtime, Function, Error};
use nova_core::process::Process;
use std::sync::{Arc, Mutex};

pub struct ScriptEngine {
    _rt: Runtime,
    ctx: Context,
    process: Arc<Mutex<Option<Process>>>,
}

impl ScriptEngine {
    pub fn new() -> Self {
        let rt = Runtime::new().unwrap();
        let ctx = Context::full(&rt).unwrap();

        let engine = Self {
            _rt: rt,
            ctx,
            process: Arc::new(Mutex::new(None)),
        };

        engine.init_globals();
        engine
    }

    fn init_globals(&self) {
        let process_clone = self.process.clone();

        self.ctx.with(|ctx| {
            let globals = ctx.globals();

            let attach_clone = process_clone.clone();
            globals.set("NovaAttach", Function::new(ctx.clone(), move |pid: i32| -> Result<(), Error> {
                let p = Process::new(pid);
                if let Err(e) = p.attach() {
                    println!("Failed to attach: {}", e);
                    return Ok(());
                }
                *attach_clone.lock().unwrap() = Some(p);
                Ok(())
            })).unwrap();

            let read_clone = process_clone.clone();
            globals.set("NovaReadMemory", Function::new(ctx.clone(), move |addr: f64, len: i32| -> Vec<u8> {
                let lock = read_clone.lock().unwrap();
                if let Some(ref p) = *lock {
                    if let Ok(data) = p.read_memory(addr as usize, len as usize) {
                        return data;
                    }
                }
                vec![]
            })).unwrap();

            globals.set("print", Function::new(ctx.clone(), |msg: String| {
                println!("{}", msg);
            })).unwrap();
        });
    }

    pub fn execute(&self, script: &str) -> Result<(), String> {
        self.ctx.with(|ctx| {
            match ctx.eval::<(), _>(script) {
                Ok(_) => Ok(()),
                Err(rquickjs::Error::Exception) => {
                    let ex = ctx.catch();
                    Err(format!("JS Exception: {:?}", ex.as_value()))
                },
                Err(e) => Err(format!("Script error: {:?}", e))
            }
        })
    }
}
