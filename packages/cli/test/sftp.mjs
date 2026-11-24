import ssh2 from "ssh2";
const { utils } = ssh2;
const { STATUS_CODE, OPEN_MODE } = utils.sftp;
export function installSftp(sftp, files) {
  const handles = new Map(); let sequence = 0;
  const attrs = (file) => ({ mode: file === "/tmp" ? 0o40700 : 0o100600, uid: 1000, gid: 1000, size: files.get(file)?.length ?? 0, atime: 0, mtime: 0 });
  sftp.on("STAT", (id, file) => files.has(file) || file === "/tmp" ? sftp.attrs(id, attrs(file)) : sftp.status(id, STATUS_CODE.NO_SUCH_FILE));
  sftp.on("FSTAT", (id, handle) => sftp.attrs(id, attrs(handles.get(handle.toString()))));
  sftp.on("OPEN", (id, file, flags) => {
    if (!files.has(file) && !(flags & OPEN_MODE.CREAT)) return sftp.status(id, STATUS_CODE.NO_SUCH_FILE);
    if (flags & OPEN_MODE.TRUNC || !files.has(file)) files.set(file, Buffer.alloc(0));
    const handle = Buffer.from(String(++sequence)); handles.set(handle.toString(), file); sftp.handle(id, handle);
  });
  sftp.on("WRITE", (id, handle, offset, data) => {
    const file = handles.get(handle.toString()), previous = files.get(file), next = Buffer.alloc(Math.max(previous.length, offset + data.length));
    previous.copy(next); data.copy(next, offset); files.set(file, next); sftp.status(id, STATUS_CODE.OK);
  });
  sftp.on("READ", (id, handle, offset, length) => {
    const file = files.get(handles.get(handle.toString()));
    if (offset >= file.length) sftp.status(id, STATUS_CODE.EOF);
    else sftp.data(id, file.subarray(offset, offset + length));
  });
  sftp.on("CLOSE", (id, handle) => { handles.delete(handle.toString()); sftp.status(id, STATUS_CODE.OK); });
}
