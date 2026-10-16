package com.termai.unidbg;

import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.arm.backend.DynarmicFactory;
import com.github.unidbg.arm.backend.Unicorn2Factory;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.dvm.DalvikModule;
import com.github.unidbg.linux.android.dvm.DvmClass;
import com.github.unidbg.linux.android.dvm.VM;
import com.github.unidbg.linux.android.dvm.jni.ProxyClassFactory;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.pointer.UnidbgPointer;
import com.github.unidbg.arm.context.RegisterContext;
import com.github.unidbg.debugger.Debugger;
import com.github.unidbg.hook.hookzz.HookZz;
import com.github.unidbg.hook.hookzz.IHookZz;
import com.github.unidbg.hook.hookzz.WrapCallback;
import com.github.unidbg.hook.hookzz.Instrument;
import com.github.unidbg.hook.hookzz.HookEntryInfo;
import com.github.unidbg.hook.arm64.HookZzArm64Handler;
import com.github.unidbg.hook.arm64.HookZzArm64;
import com.github.unidbg.arm.ARMEmulator;
import com.sun.jna.Pointer;

import java.io.File;
import java.util.*;

/**
 * TermAI unidbg CLI — 给 AI 用的 ARM64 .so 黑盒分析器
 *
 * 命令:
 *   info  <so>                          列出导出函数
 *   call  <so> <func> [hexArgs...]      调用导出函数 (参数按 hex/dec, 返回 x0)
 *   jni   <so> <class> <method> [args]  调用 JNI 方法 (Java 层)
 *   trace <so> <func> [hexArgs...]      调用并追踪指令流
 *   str   <so> <func> <strarg>          以字符串参数调用, dump 结果字符串
 *
 * 输出: 结构化 JSON (便于 AI 解析), 每行一条结果
 */
public class TermAIUnidbg {

    private AndroidEmulator emulator;
    private VM vm;
    private Module module;
    private final String soPath;
    private final int sdk = 23;

    public TermAIUnidbg(String soPath, boolean useDynarmic) {
        this.soPath = soPath;
        try {
            AndroidEmulatorBuilder builder = AndroidEmulatorBuilder.for64Bit()
                    .setProcessName("com.termai.probe");
            builder.addBackendFactory(useDynarmic
                    ? new DynarmicFactory(true)
                    : new Unicorn2Factory(true));
            emulator = builder.build();
            Memory memory = emulator.getMemory();
            memory.setLibraryResolver(new AndroidResolver(sdk));
            vm = emulator.createDalvikVM();
            vm.setDvmClassFactory(new ProxyClassFactory());
            vm.setVerbose(false);
        } catch (Throwable t) {
            err("emulator init failed: " + t);
        }
    }

    private void loadLib() {
        if (module != null) return;
        File f = new File(soPath);
        if (!f.exists()) { err("so not found: " + soPath); return; }
        try {
            DalvikModule dm = vm.loadLibrary(f, false);
            dm.callJNI_OnLoad(emulator);
            module = dm.getModule();
            out("{\"event\":\"loaded\",\"base\":\"" + module.base + "\",\"size\":"
                    + (module.size) + ",\"name\":\"" + module.name + "\"}");
        } catch (Throwable t) {
            err("loadLibrary failed: " + t);
        }
    }

    // ---- info: 列导出 ----
    public void info() {
        loadLib();
        if (module == null) return;
        // 新版 unidbg: getExports() 已移除, 用 getExportedSymbols()
        java.util.List<com.github.unidbg.Symbol> syms = new ArrayList<>(module.getExportedSymbols());
        Collections.sort(syms, new java.util.Comparator<com.github.unidbg.Symbol>() {
            public int compare(com.github.unidbg.Symbol a, com.github.unidbg.Symbol b) {
                return a.getName().compareTo(b.getName());
            }
        });
        System.out.println("{\"event\":\"exports\",\"count\":" + syms.size() + "}");
        for (com.github.unidbg.Symbol s : syms) {
            System.out.println("  {\"name\":\"" + s.getName() + "\",\"addr\":\"0x"
                    + Long.toHexString(s.getAddress()) + "\"}");
        }
    }

    // ---- call: 调函数 ----
    public void call(String func, long[] args) {
        loadLib();
        if (module == null) return;
        com.github.unidbg.Symbol fn = module.findSymbolByName(func);
        if (fn == null || fn.isUndef()) { err("export not found: " + func); return; }
        try {
            // 用 emulator 调用: 传 Number[] 参数
            Number[] nArgs = new Number[args.length];
            for (int i = 0; i < args.length; i++) nArgs[i] = args[i];
            Number ret = fn.call(emulator, nArgs);
            out("{\"event\":\"call\",\"func\":\"" + func + "\",\"ret\":\"" + ret
                    + "\",\"ret_u64\":" + ret.longValue() + "}");
        } catch (Throwable t) {
            err("call failed: " + t);
        }
    }

    // ---- jni: 调 JNI ----
    public void jni(String className, String method, String[] sargs) {
        loadLib();
        if (module == null) return;
        try {
            DvmClass c = vm.resolveClass(className.replace('.', '/'));
            Object[] args = new Object[sargs.length];
            for (int i = 0; i < sargs.length; i++) {
                args[i] = vm.addLocalObject(new com.github.unidbg.linux.android.dvm.StringObject(vm, sargs[i]));
            }
            // 尝试调用
            Object ret = c.callStaticJniMethodObject(emulator, method, args);
            out("{\"event\":\"jni\",\"class\":\"" + className + "\",\"method\":\""
                    + method + "\",\"ret\":\"" + ret + "\"}");
        } catch (Throwable t) {
            err("jni failed: " + t);
        }
    }

    // ---- str: 字符串参数 ----
    public void str(String func, String argName) {
        loadLib();
        if (module == null) return;
        com.github.unidbg.Symbol fn = module.findSymbolByName(func);
        if (fn == null || fn.isUndef()) { err("export not found: " + func); return; }
        try {
            // 分配字符串到内存
            UnidbgPointer p = emulator.getMemory().malloc(argName.length() + 1, true).getPointer();
            p.write(0, argName.getBytes("UTF-8"), 0, argName.length());
            long addr = p.peer;
            out("{\"event\":\"strarg\",\"addr\":\"0x" + Long.toHexString(addr) + "\"}");
            Number ret = fn.call(emulator, addr);
            out("{\"event\":\"str\",\"func\":\"" + func + "\",\"ret\":" + ret.longValue() + "}");
            // 尝试 dump 返回指针处字符串
            try {
                UnidbgPointer rp = UnidbgPointer.pointer(emulator, ret.longValue());
                if (rp != null) {
                    String s = rp.getString(0);
                    out("{\"event\":\"ret_string\",\"value\":" + jsonStr(s) + "}");
                }
            } catch (Throwable ignore) {}
        } catch (Throwable t) {
            err("str failed: " + t);
        }
    }

    // ---- trace: 指令追踪 ----
    public void trace(String func, long[] args) {
        loadLib();
        if (module == null) return;
        com.github.unidbg.Symbol fn = module.findSymbolByName(func);
        if (fn == null || fn.isUndef()) { err("export not found: " + func); return; }
        // 直接调用并记录耗时（指令级 hook 依赖后端支持，这里做基础耗时/返回值追踪）
        try {
            Number[] nArgs = new Number[args.length];
            for (int i = 0; i < args.length; i++) nArgs[i] = args[i];
            long t0 = System.currentTimeMillis();
            Number ret = fn.call(emulator, nArgs);
            long dt = System.currentTimeMillis() - t0;
            out("{\"event\":\"trace\",\"func\":\"" + func + "\",\"ret\":\"" + ret
                    + "\",\"ms\":" + dt + "}");
        } catch (Throwable t) {
            err("trace failed: " + t);
        }
    }

    // ---- 工具 ----
    private static void out(String s) { System.out.println(s); }
    private static void err(String s) { System.out.println("{\"error\":" + jsonStr(s) + "}"); }
    private static String jsonStr(String s) {
        if (s == null) return "null";
        StringBuilder sb = new StringBuilder("\"");
        for (char c : s.toCharArray()) {
            switch (c) {
                case '"': sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                default:
                    if (c < 0x20) sb.append(String.format("\\u%04x", (int) c));
                    else sb.append(c);
            }
        }
        return sb.append("\"").toString();
    }

    // ---- main ----
    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            System.out.println("用法: unidbg-cli <cmd> <so> [args...]");
            System.out.println("  cmd: info | call | jni | trace | str");
            System.exit(1);
        }
        String cmd = args[0];
        String so = args[1];
        boolean dynarmic = System.getenv("UNIDBG_DYNARMIC") == null
                || !System.getenv("UNIDBG_DYNARMIC").equals("0");
        TermAIUnidbg t = new TermAIUnidbg(so, dynarmic);
        try {
            switch (cmd) {
                case "info":
                    t.info(); break;
                case "call": {
                    if (args.length < 3) { t.err("need func"); break; }
                    long[] a = new long[args.length - 3];
                    for (int i = 3; i < args.length; i++) a[i-3] = parseNum(args[i]);
                    t.call(args[2], a); break;
                }
                case "jni": {
                    if (args.length < 4) { t.err("need class method"); break; }
                    String[] sa = Arrays.copyOfRange(args, 4, args.length);
                    t.jni(args[2], args[3], sa); break;
                }
                case "trace": {
                    long[] a = new long[Math.max(0, args.length - 3)];
                    for (int i = 3; i < args.length; i++) a[i-3] = parseNum(args[i]);
                    t.trace(args[2], a); break;
                }
                case "str": {
                    if (args.length < 4) { t.err("need func str"); break; }
                    t.str(args[2], args[3]); break;
                }
                default: t.err("unknown cmd: " + cmd);
            }
        } finally {
            try { t.emulator.close(); } catch (Throwable ignore) {}
        }
    }

    static long parseNum(String s) {
        try {
            if (s.startsWith("0x") || s.startsWith("0X")) return Long.parseLong(s.substring(2), 16);
            return Long.parseLong(s);
        } catch (Exception e) {
            // 当字符串处理: 分配由 str 命令负责, 这里退回 hash
            return s.hashCode();
        }
    }
}
