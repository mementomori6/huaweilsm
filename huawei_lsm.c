/*
该文件为对象管理器，即LSM各个钩子点具体实现的源码文件。
由于整个系统的安全管理器部分以及策略配置工具部分还没有完成，该源文件主要是单独测试用的。
测试能否对特定的主客体访问进行控制，而没有引入过多的策略。
等到其他部分完成后将修改该文件已配合其他部分的工作，组成完整的系统。
*/
//安全模块
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
//#include <linux/moduleparam.h>
#include <linux/security.h>
#include <linux/mm.h>
#include <linux/uaccess.h>
#include <linux/fcntl.h>//for O_RDONLY
#include <linux/fs.h>//for file_open
#include <linux/uaccess.h>//for get_fs
#include <linux/limits.h>//for PATH_MAX 
#include <linux/sched.h>
#include "security_sever.h"

#define MAX_LENGTH 256
int enable_flag = 0;
struct policydb policydb;
char controlledmessage[8192];
//控制类别
#define FILE_CONTROL 0 //文件
#define DIR_CONTROL 1 //目录
#define DB_CONTROL 2 //数据库
#define IO_CONTROL 3 //IO设备
#define DDL_CONTROL 4 //动态链接库
#define NETWORK_CONTROL 5 //网络通信
//文件访问类
#define APPEND_AUTHORITY 1 //append
#define EXEC_AUTHORITY 2 //execute
#define LINK_AUTHORITY 4 //link
#define READ_AUTHORITY 8 //read
#define RENAME_AUTHORITY 16 //rename
#define UNLINK_AUTHORITY 32 //unlink
#define WRITE_AUTHORITY 64 //写文件权限值

//目录类
#define REPARENT_AUTHORITY 1 //修改父目录权限值
#define RMDIR_AUTHORITY 2 //删除目录权限值

//数据库类
#define DDL_AUTHORITY 1 //需访问动态链接库
#define LOCALHOST_AUTHORITY 2 //通过本地 localhost
#define DB_CONNECT_AUTHORITY 4 //通过本地127.0.0.1

//IO设备类
#define MKNOD_AUTHORITY 1 //mknod
#define MOUNT_AUTHORITY 2 //mount

//动态链接库类，与文件控制类似
#define DDL_APPEND_AUTHORITY 1
#define DDL_EXEC_AUTHORITY 2
#define DDL_LINK_AUTHORITY 4
#define DDL_READ_AUTHORITY 8
#define DDL_RENAME_AUTHORITY 16
#define DDL_UNLINK_AUTHORITY 32
#define DDL_WRITE_AUTHORITY 64
#define DDL_SETATTR_AUTHORITY 128 //setattr
//网络通信类
#define BIND_AUTHORITY 1 //bind
#define CONNECT_AUTHORITY 2 //connect
#define CREATE_AUTHORITY 4 //create
#define SENDMSG_AUTHORITY 8//send_msg



//得到当前进程路径
const char *get_current_process_full_path(void)
{
	if (current->mm) {
		struct vm_area_struct *vma = current->mm->mmap;
		while (vma) {
			if ((vma->vm_flags & VM_EXECUTABLE) && vma->vm_file) {
				char *buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
				char *p;
				if (buf == NULL) return NULL;
				memset(buf, 0, PAGE_SIZE);
				//const struct *path = vma->vm_file->f_path;
				p = d_path(&vma->vm_file->f_path, buf, PAGE_SIZE);
				if (!IS_ERR(p)) {
					memmove(buf, p, strlen(p) + 1);
					//printk("%s \n",buf);
					return (const char *) buf;
				}
				kfree(buf); return NULL;
			}
			vma = vma->vm_next;
		}
	}
	return NULL;
}
//得到客体路径
static char* get_process_full_path(struct task_struct * task) {    
    if(task->mm) {
        struct vm_area_struct *vma = task->mm->mmap;
        while(vma) {
            if((vma->vm_flags && VM_EXECUTABLE) && vma->vm_file) {
                char *buffer = kmalloc(PAGE_SIZE, GFP_KERNEL);
                char *p;
                memset(buffer, 0, PAGE_SIZE);
                p = d_path(&vma->vm_file->f_path, buffer, PAGE_SIZE);
                if(!IS_ERR(p)) {
                    memmove(buffer, p, strlen(p) + 1);
                    //printk("%s\n", buffer);
                    return (char*) buffer;
                }
                kfree(buffer);
                return NULL;
            }
            vma = vma->vm_next;
        }
    }
    return NULL;
}
//得到目录路径
static int get_fullpath(struct dentry *dentry, char *full_path)
{
	struct dentry *tmp_dentry = dentry;
	char tmp_path[MAX_LENGTH];
	char local_path[MAX_LENGTH];
	memset(tmp_path,0,MAX_LENGTH);
	memset(local_path,0,MAX_LENGTH);
	while (tmp_dentry != NULL)
	{
		if (!strcmp(tmp_dentry->d_iname,"/"))
			break;
		strcpy(tmp_path,"/");
		strcat(tmp_path,tmp_dentry->d_iname);
		strcat(tmp_path,local_path);
		strcpy(local_path,tmp_path);

		tmp_dentry = tmp_dentry->d_parent;
	}
	strcpy(full_path,local_path);
	return 0;
}
static int get_parentpath(struct dentry *dentry, char *full_path)
{
	struct dentry *tmp_dentry = dentry;
	char tmp_path[MAX_LENGTH];
	char local_path[MAX_LENGTH];
	memset(tmp_path,0,MAX_LENGTH);
	memset(local_path,0,MAX_LENGTH);
	if(tmp_dentry->d_parent != NULL){
		tmp_dentry = tmp_dentry->d_parent;
	}
	while (tmp_dentry != NULL)
	{
		if (!strcmp(tmp_dentry->d_iname,"/"))
			break;
		strcpy(tmp_path,"/");
		strcat(tmp_path,tmp_dentry->d_iname);
		strcat(tmp_path,local_path);
		strcpy(local_path,tmp_path);

		tmp_dentry = tmp_dentry->d_parent;
	}
	strcpy(full_path,local_path);
	return 0;
}
//重载钩子点函数
/* int check(char* currentProcessFullPath, int authority) {
    if (enable_flag == 0) {
        return 0;
    }
    else if(currentProcessFullPath == NULL) {
        //printk("currentProcessFullPath is null\n");
        return 0;
    }
    int i;
    for (i = 0; i < ruleNumber; ++i) {
        if(strncmp(controlledRules[i], currentProcessFullPath, strlen(currentProcessFullPath)) == 0) {
            //切割字符串
            char r_authoriy[MAX_LENGTH];
            char* endptr;
            char r_path[MAX_LENGTH];
            strcpy(r_authoriy, controlledRules[i]);
            char* const delim = " "; 
            char *token, *cur = r_authoriy;
            int j = 0;
            while (token = strsep(&cur, delim)) {  
                if(j == 0) {
                    strcpy(r_path, token);
                }
                else if(j == 1) {
                    strcpy(r_authoriy, token);
                }
                j++;
            }

            
            unsigned long r_authoriy_unsigned_long = simple_strtol(r_authoriy, &endptr, 10);

            if((r_authoriy_unsigned_long & authority) == 0) {
                return 1;
            }
            else {
                return 0;
            }
        }
    }
    return 0;
} */

//file control
static int huawei_lsm_file_permission(struct file *file, int mask) {
	//printk("huawei_lsm_file_permission\n");
    char* currentProcessFullPath = get_current_process_full_path();
	char full_path[MAX_LENGTH];
	memset(full_path,0,MAX_LENGTH);
	struct dentry *dentry = file->f_dentry;
	get_fullpath(dentry,full_path);
	printk("full_path = %s",full_path);
	int operation = 0;
	if(mask == MAY_WRITE){
		operation = WRITE_AUTHORITY;
	}else{
		if(mask == MAY_READ){
		operation = READ_AUTHORITY;
		}else{
			return 0;
		}
	}
	int result = wl_avtab_check(currentProcessFullPath,full_path,FILE_CONTROL,operation,&policydb);
	int resultddl = wl_avtab_check(currentProcessFullPath,full_path,DDL_CONTROL,operation,&policydb);
	if(result != -1)
		return result;
	if(resultddl != -1)
		return resultddl;
	int target_type = obj_type_map_check(full_path,&policydb);
	int source_type = sub_dom_map_check(currentProcessFullPath,&policydb);
	result = te_avtab_check(source_type,target_type,FILE_CONTROL,operation,&policydb);
	resultddl = te_avtab_check(source_type,target_type,DDL_CONTROL,operation,&policydb);
	if(result ==1 || resultddl == 1)
		return 1;
	return 0;
}

static int huawei_lsm_inode_link (struct dentry *old_dentry,struct inode *dir, struct dentry *new_dentry){
	char full_path[MAX_LENGTH];
	printk("huawei_lsm_inode_link\n");
	memset(full_path,0,MAX_LENGTH);
	get_fullpath(new_dentry,full_path);
	printk("full_path = %s\n",full_path);
	char *currentProcess = get_current_process_full_path();
	printk("currentProcess = %s\n",currentProcess);
	int result = wl_avtab_check(currentProcess,full_path,FILE_CONTROL,LINK_AUTHORITY,&policydb);
	printk("result = %d\n",result);
	int resultddl = wl_avtab_check(currentProcess,full_path,DDL_CONTROL,DDL_LINK_AUTHORITY,&policydb);
	printk("resultddl = %d\n",resultddl);
	if(result != -1)
		return result;
	if(resultddl != -1)
		return resultddl;
	int target_type = obj_type_map_check(full_path,&policydb);
	int source_type = sub_dom_map_check(currentProcess,&policydb);
	result = te_avtab_check (source_type,target_type,FILE_CONTROL,LINK_AUTHORITY,&policydb);
	printk("result = %d\n",result);
	resultddl = te_avtab_check (source_type,target_type,DDL_CONTROL,DDL_LINK_AUTHORITY,&policydb);
	printk("resultddl = %d\n",resultddl);
	if(result == 1 || resultddl == 1)
		return 1;
	return 0;
}
static int huawei_lsm_inode_symlink (struct inode *dir,struct dentry *dentry, const char *old_name){
	char full_path[MAX_LENGTH];
	printk("huawei_lsm_inode_symlink\n");
	memset(full_path,0,MAX_LENGTH);
	get_fullpath(dentry,full_path);
	char *currentProcess = get_current_process_full_path();
	int result = wl_avtab_check(currentProcess,full_path,FILE_CONTROL,LINK_AUTHORITY,&policydb);
	int resultddl = wl_avtab_check(currentProcess,full_path,DDL_CONTROL,DDL_LINK_AUTHORITY,&policydb);
	if(result != -1)
		return result;
	if(resultddl != -1)
		return resultddl;
	int target_type = obj_type_map_check(full_path,&policydb);
	int source_type = sub_dom_map_check(currentProcess,&policydb);
	result = te_avtab_check (source_type,target_type,FILE_CONTROL,LINK_AUTHORITY,&policydb);
	resultddl = te_avtab_check (source_type,target_type,DDL_CONTROL,DDL_LINK_AUTHORITY,&policydb);
	if(result == 1 || resultddl == 1)
		return 1;
	return 0;
}
static int huawei_lsm_inode_rename (struct inode *old_dir, struct dentry *old_dentry,struct inode *new_dir, struct dentry *new_dentry){
	printk("huawei_lsm_inode_rename\n");
	char full_path[MAX_LENGTH];
	memset(full_path,0,MAX_LENGTH);
	get_fullpath(old_dentry,full_path);
	//printk("full_path = %s\n",full_path);
	char old_parent_full_path[MAX_LENGTH];
	//struct dentry *useDentry = d_find_alias(old_dir);
	memset(old_parent_full_path,0,MAX_LENGTH);
	//get_fullpath(useDentry,old_parent_full_path);
	get_parentpath(old_dentry,old_parent_full_path);
	//printk("old_parent_full_path = %s\n",old_parent_full_path);
	char new_parent_full_path[MAX_LENGTH];
	//struct dentry *useDentry_new = d_find_alias(new_dir);
	memset(new_parent_full_path,0,MAX_LENGTH);
	get_parentpath(new_dentry,new_parent_full_path);
	//printk("new_parent_full_path = %s\n",new_parent_full_path);
	char *currentProcess = get_current_process_full_path();
	//printk("currentProcess = %s\n",currentProcess);
	int result = wl_avtab_check(currentProcess,full_path,FILE_CONTROL,RENAME_AUTHORITY,&policydb);
	//printk("result = %d\n",result);
	int resultddl = wl_avtab_check(currentProcess,full_path,DDL_CONTROL,DDL_RENAME_AUTHORITY,&policydb);
	int resultRE = 0;
	return 0;
	//printk("resultddl = %d\n",resultddl);
	if(strcmp(old_parent_full_path,new_parent_full_path)!=0){
		resultRE = wl_avtab_check(currentProcess,full_path,DIR_CONTROL,REPARENT_AUTHORITY,&policydb);
		if(resultRE == 1)
			return resultRE;
	}
	//printk("resultRE = %d\n",resultRE);
	if(result != -1)
		return result;
	if(resultddl != -1)
		return resultddl;
	int target_type = obj_type_map_check(full_path,&policydb);
	int source_type = sub_dom_map_check(currentProcess,&policydb);
	result = te_avtab_check (source_type,target_type,FILE_CONTROL,RENAME_AUTHORITY,&policydb);
	printk("result = %d\n",result);
	resultddl = te_avtab_check (source_type,target_type,DDL_CONTROL,DDL_RENAME_AUTHORITY,&policydb);
	printk("resultddl = %d\n",resultddl);
	if(strcmp(old_parent_full_path,new_parent_full_path)!=0){
		resultRE = te_avtab_check (source_type,target_type,DIR_CONTROL,REPARENT_AUTHORITY,&policydb);
		if(resultRE == 1)
			return resultRE;
	}
	if(result == 1 || resultddl == 1)
		return 1;
	return 0;
}
static int huawei_lsm_inode_unlink(struct inode *dir, struct dentry *dentry) {
    printk("huawei_lsm_inode_unlink\n");
	char full_path[MAX_LENGTH];
	memset(full_path,0,MAX_LENGTH);
	get_fullpath(dentry,full_path);
	char *currentProcess = get_current_process_full_path();
	int result = wl_avtab_check(currentProcess,full_path,FILE_CONTROL,UNLINK_AUTHORITY,&policydb);
	int resultddl = wl_avtab_check(currentProcess,full_path,DDL_CONTROL,DDL_UNLINK_AUTHORITY,&policydb);
	if(result != -1)
		return result;
	if(resultddl != -1)
		return resultddl;
	int target_type = obj_type_map_check(full_path,&policydb);
	//printk("target_type = %d\n",target_type);
	int source_type = sub_dom_map_check(currentProcess,&policydb);
	//printk("source_type = %d\n",source_type);
	result = te_avtab_check (source_type,target_type,FILE_CONTROL,UNLINK_AUTHORITY,&policydb);
	resultddl = te_avtab_check (source_type,target_type,DDL_CONTROL,DDL_UNLINK_AUTHORITY,&policydb);
	if(result == 1 || resultddl == 1)
		return 1;
	return 0;
}

static int huawei_lsm_inode_rmdir(struct inode *dir, struct dentry *dentry) {
	printk("huawei_lsm_inode_rmdir\n");
	char full_path[MAX_LENGTH];
	memset(full_path,0,MAX_LENGTH);
	get_fullpath(dentry,full_path);
	char *currentProcess = get_current_process_full_path();
	int result = wl_avtab_check(currentProcess,full_path,DIR_CONTROL,RMDIR_AUTHORITY,&policydb);
	if(result != -1)
		return result;
	int target_type = obj_type_map_check(full_path,&policydb);
	int source_type = sub_dom_map_check(currentProcess,&policydb);
	result = te_avtab_check (source_type,target_type,DIR_CONTROL,RMDIR_AUTHORITY,&policydb);
	return result;
}

//database
static int huawei_lsm_socket_connect(struct socket *sock, struct sockaddr *address, int addrlen) {
    
}

//I/O device
static int huawei_lsm_sb_mount(const char *dev_name, struct path *path, const char *type, unsigned long flags, void *data) {
    printk("huawei_lsm_sb_mount %s\n",dev_name);
	char *currentProcess = get_current_process_full_path();
	int result = wl_avtab_check(currentProcess,dev_name,IO_CONTROL,MOUNT_AUTHORITY,&policydb);
	if(result != -1)
		return result;
	int target_type = obj_type_map_check(dev_name,&policydb);
	int source_type = sub_dom_map_check(currentProcess,&policydb);
	result = te_avtab_check (source_type,target_type,IO_CONTROL,MOUNT_AUTHORITY,&policydb);
	return result;
}

static int huawei_lsm_inode_mknod (struct inode *dir, struct dentry *dentry,int mode, dev_t dev){
	printk("huawei_lsm_inode_mknod \n");
	char full_path[MAX_LENGTH];
	memset(full_path,0,MAX_LENGTH);
	get_fullpath(dentry,full_path);
	char *currentProcess = get_current_process_full_path();
	int result = wl_avtab_check(currentProcess,full_path,IO_CONTROL,MKNOD_AUTHORITY,&policydb);
	if(result != -1)
		return result;
	int target_type = obj_type_map_check(full_path,&policydb);
	int source_type = sub_dom_map_check(currentProcess,&policydb);
	result = te_avtab_check (source_type,target_type,IO_CONTROL,MKNOD_AUTHORITY,&policydb);
	return result;
}

//network conmunication control				
static int huawei_lsm_socket_sendmsg (struct socket *sock,struct msghdr *msg, int size){}
static int huawei_lsm_socket_bind (struct socket *sock,struct sockaddr *address, int addrlen){}	


//ddl,exec				
static int huawei_lsm_inode_setattr	(struct dentry *dentry, struct iattr *attr){
	printk("huawei_lsm_inode_setattr %o\n",attr->ia_mode);
	char full_path[MAX_LENGTH];
	memset(full_path,0,MAX_LENGTH);
	get_fullpath(dentry,full_path);
	char *currentProcess = get_current_process_full_path();
	int result = wl_avtab_check(currentProcess,full_path,DDL_CONTROL,DDL_SETATTR_AUTHORITY,&policydb);
	if(result != -1)
		return result;
	int target_type = obj_type_map_check(full_path,&policydb);
	int source_type = sub_dom_map_check(currentProcess,&policydb);
	result = te_avtab_check (source_type,target_type,DDL_CONTROL,DDL_SETATTR_AUTHORITY,&policydb);
	return result;
}				
				
static int huawei_lsm_inode_permission(struct inode *inode, int mask) {
    if(mask == MAY_READ || mask == MAY_WRITE || mask != MAY_EXEC && mask != MAY_APPEND)
		return 0;
	int inodeMode = inode->i_mode & 4095;
	//printk("huawei_lsm_inode_permission %d\n",inodeMode);
	char full_path[MAX_LENGTH];
	struct dentry *useDentry = d_find_alias(inode);
	memset(full_path,0,MAX_LENGTH);
	get_fullpath(useDentry,full_path);
	if(strlen(full_path) == 0)
		return 0;
	return 0;	
	char *currentProcess = get_current_process_full_path();
	
	if(mask == MAY_EXEC){
		int ddlresult = wl_avtab_check(currentProcess,full_path,FILE_CONTROL,EXEC_AUTHORITY,&policydb);
		int fileresult = wl_avtab_check(currentProcess,full_path,DDL_CONTROL,DDL_EXEC_AUTHORITY,&policydb);
		if(fileresult != -1)
			return fileresult;
		if(ddlresult != -1)
			return ddlresult;
		int target_type = obj_type_map_check(full_path,&policydb);
		int source_type = sub_dom_map_check(currentProcess,&policydb);
		ddlresult = te_avtab_check (source_type,target_type,DDL_CONTROL,DDL_EXEC_AUTHORITY,&policydb);
		fileresult = te_avtab_check (source_type,target_type,FILE_CONTROL,EXEC_AUTHORITY,&policydb);
		if(fileresult == 1 || ddlresult == 1)
			return 1;
		return 0;
	}
	if(mask == MAY_APPEND){
		int ddlresult = wl_avtab_check(currentProcess,full_path,FILE_CONTROL,APPEND_AUTHORITY,&policydb);
		int fileresult = wl_avtab_check(currentProcess,full_path,DDL_CONTROL,DDL_APPEND_AUTHORITY,&policydb);
		if(fileresult != -1)
			return fileresult;
		if(ddlresult != -1)
			return ddlresult;
		int target_type = obj_type_map_check(full_path,&policydb);
		int source_type = sub_dom_map_check(currentProcess,&policydb);
		ddlresult = te_avtab_check (source_type,target_type,DDL_CONTROL,DDL_EXEC_AUTHORITY,&policydb);
		fileresult = te_avtab_check (source_type,target_type,FILE_CONTROL,DDL_APPEND_AUTHORITY,&policydb);
		if(fileresult == 1 || ddlresult == 1)
			return 1;
		return 0;
	}
	return 0;
}

/* static int huawei_lsm_task_create(unsigned long clone_flags) {
    char* currentProcessFullPath = get_current_process_full_path();

    if(check(currentProcessFullPath, EXEC_AUTHORITY) != 0) {
        printk("exec denied\n");
        return -1;
    }
    else {
        return 0;
    }
} */

//初始化模块
 void initialize_subject_domainMapping(struct policydb *policydb)
{
	policydb->sub_dom_map_use = 0;
	policydb->sdmap_policy_num = 0;
	int i = 0;
	int size = policydb->sub_dom_map_size;
	for( i = 0;i<size;++i){
		if(policydb->sub_dom_map->sdmap_node[i] != NULL){
			free_sdmap_node_list(policydb->sub_dom_map->sdmap_node[i]);
			policydb->sub_dom_map->sdmap_node[i] = NULL;
		}
	}
}
 void initialize_object_typeMapping(struct policydb *policydb)
{
	policydb->obj_type_map_use = 0;
	policydb->otmap_policy_num = 0;
	int i = 0;
	int size = policydb->obj_type_map_size;
	for(i = 0;i<size;++i){
		if(policydb->obj_type_map->objtype_node[i] != NULL){
			free_objtype_node_list(policydb->obj_type_map->objtype_node[i] );
			policydb->obj_type_map->objtype_node[i] = NULL;
		}
	}
}
 void initialize_whiteList(struct policydb *policydb)
{
	policydb->wl_avtab_use = 0;
	policydb->wl_policy_num = 0;
	int i = 0;
	int size = policydb->wl_avtab_size;
	for(i = 0;i<size;++i){
		if(policydb->wl_avtab->wl_avtab_node[i] != NULL){
			free_wl_avtab_node_list(policydb->wl_avtab->wl_avtab_node[i]);
			policydb->wl_avtab->wl_avtab_node[i] = NULL;
		}
	}
}
 void initialize_accessControlMatrix(struct policydb *policydb)
{
	policydb->te_avtab_use = 0;
	policydb->te_policy_num = 0;
	int i = 0;
	int size = policydb->te_avtab_size;
	for(i = 0;i<size;++i){
		if(policydb->te_avtab->te_node[i] != NULL){
			free_te_node_list(policydb->te_avtab->te_node[i]);
			policydb->te_avtab->te_node[i] = NULL;
		}
	}
}


//安全策略解析
static int write_object_typeMapping(int fd, char *buf, ssize_t len)
{
	initialize_object_typeMapping(&policydb);
	memset(controlledmessage,0,8192);
	if(len == 0)
		return len;
	if (copy_from_user(controlledmessage, buf, len) != 0){
		printk("Can't get the controlled directory's name! \n");
		printk("Something may be wrong, please check it! \n");
	}
	//test!
	strcpy(controlledmessage,buf);
	controlledmessage[len] = '\0';
	enable_flag = 1;
	int readProcess = 0;
	//write rules
 		while(readProcess < len){
		//读每行数据（即一个完整数据）
		while(controlledmessage[readProcess]!='\n'){
			//读数据开头
			while(controlledmessage[readProcess]!='#'){
				++readProcess;
			}
			++readProcess;
			//读obj_name
			char obj_name[MAX_LENGTH];
			memset(obj_name,0,MAX_LENGTH);
			int source_count = 0;
			while(controlledmessage[readProcess]!='#'){
				obj_name[source_count++] = controlledmessage[readProcess];
				++readProcess;
			}
			obj_name[source_count]='\0';
			printk("obj_name = %s\n",obj_name);
			++readProcess;
			//读obj_domain_name(不读取)
			while(controlledmessage[readProcess]!='#'){
				printk("%c",controlledmessage[readProcess]);
				++readProcess;
			}
			++readProcess;
			//读obj_type
			int obj_type = 0;
			while(controlledmessage[readProcess]!='\n'){
				obj_type = obj_type*10;
				obj_type = obj_type + controlledmessage[readProcess] - '0';
				readProcess++;
			}
			printk("obj_type = %d\n",obj_type);
			addNewObjtype_node(
				insert_objtype_node(obj_name,obj_type),
				&policydb
			);
		}
		readProcess++;
	} 
		printk("check object type map\n");
	int counttest = 0;
	for(;counttest<499;counttest ++){
		struct objtype_node *wl_test = policydb.obj_type_map->objtype_node[counttest];
		while(wl_test != NULL){
			printk("obj_name = %s,obj_type = %d\n",
			wl_test->key->obj_name,
			wl_test->datum->obj_type);
			wl_test = wl_test->next;
		}
	}
}
static int write_subject_domainMapping(int fd, char *buf, ssize_t len)
{
	initialize_subject_domainMapping(&policydb);
	memset(controlledmessage,0,8192);
	if(len == 0)
		return len;
	if (copy_from_user(controlledmessage, buf, len) != 0){
		printk("Can't get the controlled directory's name! \n");
		printk("Something may be wrong, please check it! \n");
	}
	controlledmessage[len] = '\0';
	enable_flag = 1;
	//test!
	strcpy(controlledmessage,buf);
	//write rules
	int readProcess = 0;
 	while(readProcess < len){
		//读每行数据（即一个完整数据）
		while(controlledmessage[readProcess]!='\n'){
			//读数据开头
			while(controlledmessage[readProcess]!='#'){
				++readProcess;
			}
			++readProcess;
			//读sub_name
			char sub_name[MAX_LENGTH];
			memset(sub_name,0,MAX_LENGTH);
			int source_count = 0;
			while(controlledmessage[readProcess]!='#'){
				sub_name[source_count++] = controlledmessage[readProcess];
				++readProcess;
			}
			sub_name[source_count]='\0';
			printk("sub_name = %s\n",sub_name);
			++readProcess;
			//读domain_name(不读取)
			while(controlledmessage[readProcess]!='#'){
				++readProcess;
			}
			++readProcess;
			//读sub_domain
			int sub_domain = 0;
			while(controlledmessage[readProcess]!='\n'){
				sub_domain = sub_domain*10;
				sub_domain = sub_domain + controlledmessage[readProcess] - '0';
				readProcess++;
			}
			printk("sub_domain = %d\n",sub_domain);
			addNewSdmap_node(
				insert_sdmap_node(sub_name,sub_domain),
				&policydb
			);
		}
		readProcess++;
	} 
	printk("check subject dmain map\n");
	int counttest = 0;
	for(;counttest<499;counttest ++){
		struct sdmap_node *wl_test = policydb.sub_dom_map->sdmap_node[counttest];
		while(wl_test != NULL){
			printk("sub_name = %s,sub_domain = %d\n",
			wl_test->key->sub_name,
			wl_test->datum->sub_domain);
			wl_test = wl_test->next;
		}
	}
}
static int write_whiteList(int fd, char *buf, ssize_t len)
{
	printk("start write_whiteList\n");
	initialize_whiteList(&policydb);
	memset(controlledmessage,0,8192);
	if(len == 0)
		return len;
	if (copy_from_user(controlledmessage, buf, len) != 0){
		printk("Can't get the controlled directory's name! \n");
		printk("Something may be wrong, please check it! \n");
	}

	controlledmessage[len] = '\0';
	enable_flag = 1;
	//test!
	strcpy(controlledmessage,buf);
	//write rules
	int readProcess = 0;
 	while(readProcess < len){
		//读每行数据（即一个完整数据）
		while(controlledmessage[readProcess]!='\n'){
			//读数据开头
			while(controlledmessage[readProcess]!='#'){
				++readProcess;
			}
			++readProcess;
			//读source_name
			char source_name[MAX_LENGTH];
			memset(source_name,0,MAX_LENGTH);
			int source_count = 0;
			while(controlledmessage[readProcess]!='#'){
				source_name[source_count++] = controlledmessage[readProcess];
				++readProcess;
			}
			source_name[source_count]='\0';
			printk("source_name = %s\n",source_name);			
			++readProcess;
			//读target_name
			char target_name[MAX_LENGTH];
			memset(target_name,0,MAX_LENGTH);
			int target_count = 0;
			while(controlledmessage[readProcess]!='#'){
				target_name[target_count++] = controlledmessage[readProcess];
				++readProcess;
			}
			printk("target_name = %s\n",target_name);
			target_name[target_count]='\0';
			++readProcess;
			//读target_type（只有1位）
			int target_type = 0;
			target_type = controlledmessage[readProcess] - '0';
			readProcess++;
			readProcess++;
			printk("target_type = %d\n",target_type);
			//读permission
			int permission = 0;
			while(controlledmessage[readProcess]!='\n'&&controlledmessage[readProcess]=='0'||controlledmessage[readProcess]=='1'){
				permission = 2*permission;
				permission = permission + controlledmessage[readProcess] - '0';
				readProcess++;
			}
			printk("permission = %d\n",permission);	
			printk("start insert wl\n");
			addNewWl_avtb_node(
				insert_wl_avtab_node(source_name,target_name,target_type,permission),
				&policydb
			);
		}
		readProcess++;
	}
 
}
static int write_accessControlMatrix(int fd, char *buf, ssize_t len)
{
	initialize_accessControlMatrix(&policydb);
	memset(controlledmessage,0,8192);
	if(len == 0)
		return len;
	if (copy_from_user(controlledmessage, buf, len) != 0){
		printk("Can't get the controlled directory's name! \n");
		printk("Something may be wrong, please check it! \n");
	}
	//test!
	strcpy(controlledmessage,buf);
	//strcpy(controlledmessage,buf);
	controlledmessage[len] = '\0';
	enable_flag = 1;
	int readProcess = 0;
	//write rules
 	while(readProcess < len){
		//读每行数据（即一个完整数据）
		while(controlledmessage[readProcess]!='\n'){
			//读数据开头
			while(controlledmessage[readProcess]!='#'){
				++readProcess;
			}
			++readProcess;
			//读domain_name（不读取）
			while(controlledmessage[readProcess]!='#'){
				++readProcess;
			}
			++readProcess;
			//读域编号
			int source_type=0;
			while(controlledmessage[readProcess]!='#'){
				source_type = source_type * 10;
				source_type = source_type + controlledmessage[readProcess] - '0';
				readProcess++;
			}
			printk("source_type = %d",source_type);
			readProcess++;
			//读类型名(不读取)
			while(controlledmessage[readProcess]!='#'){
				++readProcess;
			}
			++readProcess;
			//读类型编号
			int target_type=0;
			while(controlledmessage[readProcess]!='#'){
				target_type = target_type * 10;
				target_type = target_type + controlledmessage[readProcess] - '0';
				readProcess++;
			}
			printk("target_type = %d",target_type);
			readProcess++;
			//读客体类别（只有1位）
			int target_class = 0;
			target_class = controlledmessage[readProcess] - '0';
			readProcess++;
			readProcess++;
			printk("target_class = %d",target_class);
			//读permission
			int permission = 0;
			while(controlledmessage[readProcess]!='\n'&&controlledmessage[readProcess]=='0'||controlledmessage[readProcess]=='1'){
				permission = 2*permission;
				permission = permission + controlledmessage[readProcess] - '0';
				readProcess++;
			}
			printk("permission = %d\n",permission);
			addNewTe_node(
				insert_te_node(source_type,target_type,target_class,permission),
				&policydb
			);
		}
		readProcess++;
	} 
	/*printk("check\n");
	int counttest = 0;
	for(;counttest<499;counttest ++){
		
		struct te_node *wl_test = policydb.te_avtab->te_node[counttest];
		while(wl_test != NULL){
			printk("source_name = %d,target_name = %d,target_class = %d,permission = %d\n",wl_test->key->source_type,
			wl_test->key->target_type,
			wl_test->key->target_class,
			wl_test->datum->permission);
			wl_test = wl_test->next;
		}
	} */
}	
//配置安全策略解析模块		   
struct file_operations fops0 = {
	owner:THIS_MODULE, 
	write: write_subject_domainMapping, 
};
struct file_operations fops1 = {
	owner:THIS_MODULE, 
	write: write_object_typeMapping, 
};
struct file_operations fops2 = {
	owner:THIS_MODULE, 
	write: write_whiteList, 
};
struct file_operations fops3 = {
	owner:THIS_MODULE, 
	write: write_accessControlMatrix, 
}; 

void initialpolicydb(void){
	policydb.sub_dom_map_size = HASH_MAX_LENGTH;
	policydb.sub_dom_map_use = 0;
	policydb.sdmap_policy_num = 0;
	int i = 0;
 	struct sdmap_node **sdmap_node = (struct sdmap_node **)vmalloc(policydb.sub_dom_map_size*sizeof(struct sdmap_node *));
	struct sub_dom_map *sub_dom_map = (struct sub_dom_map *)vmalloc(sizeof(struct sub_dom_map));
	policydb.sub_dom_map = sub_dom_map;
	policydb.sub_dom_map->sdmap_node = sdmap_node; 
	for( i = 0;i<policydb.sub_dom_map_size;++i){
		policydb.sub_dom_map->sdmap_node[i] = NULL;
	}
	
	
	policydb.obj_type_map_size = HASH_MAX_LENGTH;
	policydb.obj_type_map_use = 0;
	policydb.otmap_policy_num = 0;
	struct objtype_node **objtype_node = (struct objtype_node **)vmalloc(policydb.obj_type_map_size*sizeof(struct objtype_node *));
	struct obj_type_map *obj_type_map = (struct obj_type_map *)vmalloc(sizeof(struct obj_type_map));
	policydb.obj_type_map = obj_type_map;	
	policydb.obj_type_map->objtype_node = objtype_node; 
	for( i = 0;i<policydb.obj_type_map_size;++i){
		policydb.obj_type_map->objtype_node[i] = NULL;
	}
	
	
	policydb.wl_avtab_size = HASH_MAX_LENGTH;
	policydb.wl_avtab_use = 0;
	policydb.wl_policy_num = 0;
	struct wl_avtab_node **wl_avtab_node = (struct wl_avtab_node **)vmalloc(policydb.wl_avtab_size *sizeof(struct wl_avtab_node *));
	struct wl_avtab *wl_avtab = (struct wl_avtab *)vmalloc(sizeof(struct wl_avtab));
	policydb.wl_avtab = wl_avtab;
	policydb.wl_avtab->wl_avtab_node = wl_avtab_node; 
	for( i = 0;i<policydb.wl_avtab_size;++i){
		policydb.wl_avtab->wl_avtab_node[i] = NULL;
	}
	
	
	policydb.te_avtab_size = HASH_MAX_LENGTH;
	policydb.te_avtab_use = 0;
	policydb.te_policy_num = 0;
	struct te_node **te_node = (struct te_node **)vmalloc(policydb.te_avtab_size *sizeof(struct te_node *));
	struct te_avtab *te_avtab = (struct te_avtab *)vmalloc(sizeof(struct te_avtab));
	 policydb.te_avtab = te_avtab;
	policydb.te_avtab->te_node = te_node; 
	for( i = 0;i<policydb.te_avtab_size;++i){
		policydb.te_avtab->te_node[i] = NULL;
	} 
	
}
//挂载钩子点函数
static struct security_operations lsm_ops=
{
	//file control
	//.file_permission = huawei_lsm_file_permission, //file_append_execute_read_write_databaseConnect,
	//.inode_link = huawei_lsm_inode_link, //file_link,
	//.inode_symlink = huawei_lsm_inode_symlink,//file_symlink
	//.inode_rename = huawei_lsm_inode_rename, //file_rename,
	//.inode_unlink = huawei_lsm_inode_unlink, //file_inode_unlink,
	//.inode_rmdir = huawei_lsm_inode_rmdir, //rmdir,
	
	//database
	//.socket_connect = huawei_lsm_socket_connect, //localhost_127001_socketConnect,
	
	//I/O device
	//.sb_mount = huawei_lsm_sb_mount, //mount,
	//.inode_mknod = huawei_lsm_inode_mknod, //mknod,
	
	//network conmunication control
	//.socket_sendmsg = huawei_lsm_socket_sendmsg, //socketAppend,
	//.socket_bind = huawei_lsm_socket_bind, //bind_nameBind,
	//.socket_create = huawei_lsm_socket_create, //network_create,
	//.socket_connect = huawei_lsm_socket_connect, 

	//ddl,exec
	//.inode_setattr = huawei_lsm_inode_setattr,
	.inode_permission = huawei_lsm_inode_permission,
};

//载入模块
static int __init lsm_init(void)
{
	int ret_subjectDomainMapping,ret_objectTypeMapping,ret_whiteList,ret_accessControlMatrix;
    if(register_security(&lsm_ops))
          {
        printk(KERN_INFO"Failure registering LSM module with kernel\n");
           }
	
    printk(KERN_INFO"LSM Module Init Success! \n");
	initialpolicydb();
	ret_subjectDomainMapping = register_chrdev(123, "/dev/subject-domainMapping.cfg", &fops0); 	// 向系统注册设备结点文件
	printk("ret_subjectDomainMapping Init Success! %d \n",ret_subjectDomainMapping);
	ret_objectTypeMapping = register_chrdev(124, "/dev/object-typeMapping.cfg", &fops1); 	// 向系统注册设备结点文件
	printk("ret_objectTypeMapping Init Success! %d \n",ret_objectTypeMapping);
	ret_whiteList = register_chrdev(125, "/dev/whiteList.cfg", &fops2); 	// 向系统注册设备结点文件
	char* wl = "#source_name0#target_name0#3#00000010\n#source_name1#target_name1#5#00000100\n";
	write_whiteList(1,wl,strlen(wl));
	char *ac = "#domain_name 1#1#type_name1#2#1#00000001\n#domain_name 2#2#type_name2#2#3#00000010\n#domain_name 3#2#type_name3#1#5#00000100\n";
	write_accessControlMatrix(1,ac,strlen(ac));
	char *ob = "#obj_name0#log_t#1\n#obj_name1#config_t#0\n";
	char *su = "#sub_name0#admin_t#0\n#sub_name1#config_t#1\n#sub_name2#admin_t#0\n";
	write_object_typeMapping(1,ob,strlen(ob));
	write_subject_domainMapping(1,su,strlen(su));
	ret_accessControlMatrix = register_chrdev(126, "/dev/accessControlMatrix.cfg", &fops3); 	// 向系统注册设备结点文件
	printk("ret_accessControlMatrix Init Success! %d \n",ret_accessControlMatrix);
	//if (ret != 0) printk("Can't register device file! \n"); 
	

   return 0;
}
//注销模块
static void __exit lsm_exit(void)
{
    printk(KERN_INFO"LSM Module unregistered.....\n");
	unregister_chrdev(123, "procinfo");	 // 向系统注销设备结点文件 
	
}
//security_initcall(lsm_init);

module_init(lsm_init);
module_exit(lsm_exit);

MODULE_LICENSE("GPL");