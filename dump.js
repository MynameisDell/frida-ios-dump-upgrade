// Ensure the 'Foundation' module is initialized
Module.ensureInitialized('Foundation');

// Constants for file operations and memory operations
const O_RDONLY = 0;
const O_WRONLY = 1;
const O_RDWR = 2;
const O_CREAT = 512;
const SEEK_SET = 0;
const SEEK_CUR = 1;
const SEEK_END = 2;

const FAT_MAGIC = 0xcafebabe;
const FAT_CIGAM = 0xbebafeca;
const MH_MAGIC = 0xfeedface;
const MH_CIGAM = 0xcefaedfe;
const MH_MAGIC_64 = 0xfeedfacf;
const MH_CIGAM_64 = 0xcffaedfe;
const LC_SEGMENT = 0x1;
const LC_SEGMENT_64 = 0x19;
const LC_ENCRYPTION_INFO = 0x21;
const LC_ENCRYPTION_INFO_64 = 0x2C;

// Utility functions for memory operations
const memoryUtils = {
    allocStr: (str) => Memory.allocUtf8String(str),
    putStr: (addr, str) => Memory.writeUtf8String(ptr(addr), str),
    getByteArr: (addr, length) => Memory.readByteArray(ptr(addr), length),
    getU8: (addr) => Memory.readU8(ptr(addr)),
    putU8: (addr, val) => Memory.writeU8(ptr(addr), val),
    getU16: (addr) => Memory.readU16(ptr(addr)),
    putU16: (addr, val) => Memory.writeU16(ptr(addr), val),
    getU32: (addr) => Memory.readU32(ptr(addr)),
    putU32: (addr, val) => Memory.writeU32(ptr(addr), val),
    getU64: (addr) => Memory.readU64(ptr(addr)),
    putU64: (addr, val) => Memory.writeU64(ptr(addr), val),
    getPtr: (addr) => Memory.readPointer(ptr(addr)),
    putPtr: (addr, val) => Memory.writePointer(ptr(addr), ptr(val)),
    malloc: (size) => Memory.alloc(size),
    swap32: (value) => parseInt(value.toString(16).padStart(8, '0').match(/../g).reverse().join(''), 16),
};

// Function to get exported function or data
const getExport = (type, name, ret, args) => {
    const nptr = Module.findExportByName(null, name);
    if (!nptr) {
        console.error(`Cannot find ${name}`);
        return null;
    }
    return type === 'f' ? new NativeFunction(nptr, ret, args) : Memory.readPointer(nptr);
};

// Get various system functions
const NSSearchPathForDirectoriesInDomains = getExport("f", "NSSearchPathForDirectoriesInDomains", "pointer", ["int", "int", "int"]);
const openFile = getExport("f", "open", "int", ["pointer", "int", "int"]);
const readFile = getExport("f", "read", "int", ["int", "pointer", "int"]);
const writeFile = getExport("f", "write", "int", ["int", "pointer", "int"]);
const lseekFile = getExport("f", "lseek", "int64", ["int", "int64", "int"]);
const closeFile = getExport("f", "close", "int", ["int"]);
const removeFile = getExport("f", "remove", "int", ["pointer"]);
const accessFile = getExport("f", "access", "int", ["pointer", "int"]);
const dlopenLib = getExport("f", "dlopen", "pointer", ["pointer", "int"]);

// Function to get document directory path
const getDocumentDir = () => {
    const NSDocumentDirectory = 9;
    const NSUserDomainMask = 1;
    const npdirs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, 1);
    return ObjC.Object(npdirs).objectAtIndex_(0).toString();
};

// Function to open a file with error handling
const open = (pathname, flags, mode) => {
    const pathPtr = typeof pathname === 'string' ? memoryUtils.allocStr(pathname) : pathname;
    return openFile(pathPtr, flags, mode);
};

// Function to get all application modules
const getAllAppModules = () => {
    return Process.enumerateModulesSync().filter(mod => mod.path.includes('.app'));
};

// Function to dump a module
const dumpModule = (moduleName) => {
    const modules = getAllAppModules();
    const targetModule = modules.find(mod => mod.path.includes(moduleName));
    if (!targetModule) {
        console.error("Cannot find module");
        return null;
    }

    const { base: modBase, size: modSize, name: modName, path: oldModPath } = targetModule;
    const newModPath = `${getDocumentDir()}/${modName}.fid`;

    if (!accessFile(memoryUtils.allocStr(newModPath), 0)) {
        removeFile(memoryUtils.allocStr(newModPath));
    }

    const fmodule = open(newModPath, O_CREAT | O_RDWR, 0);
    const foldModule = open(oldModPath, O_RDONLY, 0);

    if (fmodule === -1 || foldModule === -1) {
        console.error(`Cannot open file ${newModPath}`);
        return null;
    }

    const BUFSIZE = 4096;
    const buffer = memoryUtils.malloc(BUFSIZE);
    readFile(foldModule, buffer, BUFSIZE);

    const magic = memoryUtils.getU32(modBase);
    const curCpuType = memoryUtils.getU32(modBase.add(4));
    const curCpuSubType = memoryUtils.getU32(modBase.add(8));

    let is64Bit = false;
    let sizeOfMachHeader = 0;
    if ([MH_MAGIC, MH_CIGAM].includes(magic)) {
        is64Bit = false;
        sizeOfMachHeader = 28;
    } else if ([MH_MAGIC_64, MH_CIGAM_64].includes(magic)) {
        is64Bit = true;
        sizeOfMachHeader = 32;
    }

    let fileOffset = 0;
    let fileSize = 0;
    if ([FAT_MAGIC, FAT_CIGAM].includes(memoryUtils.getU32(buffer))) {
        const archs = memoryUtils.swap32(memoryUtils.getU32(buffer.add(4)));
        for (let i = 0; i < archs; i++) {
            const cputype = memoryUtils.swap32(memoryUtils.getU32(buffer.add(8 + 20 * i)));
            const cpusubtype = memoryUtils.swap32(memoryUtils.getU32(buffer.add(12 + 20 * i)));
            if (curCpuType === cputype && curCpuSubType === cpusubtype) {
                fileOffset = memoryUtils.swap32(memoryUtils.getU32(buffer.add(16 + 20 * i)));
                fileSize = memoryUtils.swap32(memoryUtils.getU32(buffer.add(20 + 20 * i)));
                break;
            }
        }
        if (!fileOffset || !fileSize) return null;

        lseekFile(fmodule, 0, SEEK_SET);
        lseekFile(foldModule, fileOffset, SEEK_SET);
        for (let i = 0; i < Math.floor(fileSize / BUFSIZE); i++) {
            readFile(foldModule, buffer, BUFSIZE);
            writeFile(fmodule, buffer, BUFSIZE);
        }
        if (fileSize % BUFSIZE) {
            readFile(foldModule, buffer, fileSize % BUFSIZE);
            writeFile(fmodule, buffer, fileSize % BUFSIZE);
        }
    } else {
        lseekFile(foldModule, 0, SEEK_SET);
        lseekFile(fmodule, 0, SEEK_SET);
        let readLen = 0;
        while (readLen = readFile(foldModule, buffer, BUFSIZE)) {
            writeFile(fmodule, buffer, readLen);
        }
    }

    const ncmds = memoryUtils.getU32(modBase.add(16));
    let offsetCryptId = -1;
    let cryptOff = 0;
    let cryptSize = 0;
    let off = sizeOfMachHeader;

    for (let i = 0; i < ncmds; i++) {
        const cmd = memoryUtils.getU32(modBase.add(off));
        const cmdSize = memoryUtils.getU32(modBase.add(off + 4));
        if ([LC_ENCRYPTION_INFO, LC_ENCRYPTION_INFO_64].includes(cmd)) {
            offsetCryptId = off + 16;
            cryptOff = memoryUtils.getU32(modBase.add(off + 8));
            cryptSize = memoryUtils.getU32(modBase.add(off + 12));
        }
        off += cmdSize;
    }

    if (offsetCryptId === -1) {
        closeFile(fmodule);
        closeFile(foldModule);
        return;
    }

    lseekFile(fmodule, offsetCryptId, SEEK_SET);
    writeFile(fmodule, memoryUtils.allocStr("\x00\x00\x00\x00"), 4);
    lseekFile(fmodule, cryptOff, SEEK_SET);
    lseekFile(foldModule, modBase.add(cryptOff).sub(modBase), SEEK_SET);

    for (let i = 0; i < Math.floor(cryptSize / BUFSIZE); i++) {
        readFile(foldModule, buffer, BUFSIZE);
        writeFile(fmodule, buffer, BUFSIZE);
    }
    if (cryptSize % BUFSIZE) {
        readFile(foldModule, buffer, cryptSize % BUFSIZE);
        writeFile(fmodule, buffer, cryptSize % BUFSIZE);
    }

    closeFile(fmodule);
    closeFile(foldModule);
};

// Function to load all dynamic libraries of the application
const loadAllDynamicLibrary = () => {
    const appModules = getAllAppModules();
    appModules.forEach(mod => {
        const modPath = mod.path;
        if (modPath.endsWith('.dylib') && !Process.findModuleByName(mod.name)) {
            dlopenLib(memoryUtils.allocStr(modPath), 1);
        }
    });
};

// Handle messages from the client
const handleMessage = (message) => {
    if (message.type === 'dump') {
        const modules = getAllAppModules();
        loadAllDynamicLibrary();
        const response = modules.map(mod => {
            dumpModule(mod.name);
            return {
                name: mod.name,
                base: mod.base.toString(),
                size: mod.size,
                path: mod.path,
            };
        });
        send({ type: 'dumpResponse', payload: response });
    }
};

recv(handleMessage).wait();
