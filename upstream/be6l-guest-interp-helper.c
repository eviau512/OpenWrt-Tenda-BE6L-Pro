/* SPDX-License-Identifier: GPL-2.0-only */
/* Injected in built-in binfmt_misc only by the explicit BE6L V2 profile.
 * This checks the ELF/PT_INTERP boundary before committing native exec, and
 * returns an open_exec reference to the exact loader inode. It does not claim
 * complete ELF property, mapping, credential or standard-package qualification.
 */
#if IS_BUILTIN(CONFIG_BINFMT_MISC)
static int be6l_elf_read(struct file *file, void *buffer, size_t size, loff_t pos)
{
	ssize_t result = kernel_read(file, buffer, size, &pos);

	return result < 0 ? result : result != size ? -EIO : 0;
}

static Elf64_Phdr *be6l_elf_phdrs(struct file *file, const Elf64_Ehdr *header)
{
	unsigned int size = sizeof(Elf64_Phdr) * header->e_phnum;
	Elf64_Phdr *data;

	/* Match load_elf_phdrs' size limits and failure boundary. */
	if (header->e_phentsize != sizeof(Elf64_Phdr) || !size || size > 65536)
		return NULL;
	data = kmalloc(size, GFP_KERNEL);
	if (data && be6l_elf_read(file, data, size, header->e_phoff)) {
		kfree(data);
		data = NULL;
	}
	return data;
}

static bool be6l_a53_elf(const Elf64_Ehdr *header)
{
	return !memcmp(header->e_ident, ELFMAG, SELFMAG) &&
		header->e_ident[EI_CLASS] == ELFCLASS64 &&
		header->e_ident[EI_DATA] == ELFDATA2LSB &&
		header->e_machine == EM_AARCH64;
}

static int be6l_prepare_guest_interp(struct linux_binprm *bprm)
{
	Elf64_Ehdr header, interp_header;
	Elf64_Phdr *phdrs, *interp_phdrs;
	struct file *interpreter = NULL;
	char *name = NULL;
	int err = -ENOEXEC;
	unsigned int i;

	memcpy(&header, bprm->buf, sizeof(header));
	if (!be6l_a53_elf(&header) || header.e_flags ||
	    (header.e_type != ET_EXEC && header.e_type != ET_DYN) ||
	    !can_mmap_file(bprm->file))
		return -ENOEXEC;
	phdrs = be6l_elf_phdrs(bprm->file, &header);
	if (!phdrs)
		return -ENOEXEC;
	for (i = 0; i < header.e_phnum; i++) {
		if (phdrs[i].p_type != PT_INTERP)
			continue;
		if (phdrs[i].p_filesz < 2 || phdrs[i].p_filesz > PATH_MAX)
			goto out;
		err = -ENOMEM;
		name = kmalloc(phdrs[i].p_filesz, GFP_KERNEL);
		if (!name)
			goto out;
		err = be6l_elf_read(bprm->file, name, phdrs[i].p_filesz, phdrs[i].p_offset);
		if (err)
			goto out;
		err = -ENOEXEC;
		if (name[phdrs[i].p_filesz - 1])
			goto out;
		interpreter = open_exec(name);
		if (IS_ERR(interpreter)) {
			err = PTR_ERR(interpreter);
			interpreter = NULL;
			goto out;
		}
		would_dump(bprm, interpreter);
		err = be6l_elf_read(interpreter, &interp_header, sizeof(interp_header), 0);
		if (err)
			goto out;
		err = -ELIBBAD;
		if (!be6l_a53_elf(&interp_header) || !can_mmap_file(interpreter))
			goto out;
		interp_phdrs = be6l_elf_phdrs(interpreter, &interp_header);
		if (!interp_phdrs)
			goto out;
		kfree(interp_phdrs);
		/* open_exec owns both a ref and write denial. No close/reopen gap:
		 * mmput releases them, fork duplicates them, and a separate CLOEXEC
		 * fd lets the aware emulator map this same loader inode.
		 */
		bprm->mm->be6l_guest_loader = interpreter;
		interpreter = NULL;
		break;
	}
	err = 0;
out:
	if (interpreter) {
		exe_file_allow_write_access(interpreter);
		fput(interpreter);
	}
	kfree(name);
	kfree(phdrs);
	return err;
}
#endif
