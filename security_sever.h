/*
该文件为安全服务器设计的头文件
该文件主要定义了策略库的各个数据结构以及向对象管理器提供的策略查询接口
具体的初始化、策略加载、策略监听以及策略查询等模块正在编码中，还未完成
*/


#include <linux/kernel.h>
#include <linux/vmalloc.h>
#define  HASH_MAX_LENGTH  499 ;
// hash 
unsigned int BKDRHash(char *str)
{
    unsigned int seed = 131; // 31 131 1313 13131 131313 etc..
    unsigned int hash = 0;

    while (*str)
    {
        hash = hash * seed + (*str++);
    }

    return (hash & 0x7FFFFFFF);
}
//安全策略库数据结构设计
struct policydb{
	struct te_avtab *te_avtab;
	int te_avtab_size;	  /*哈希表的大小，通常为素数*/
	int te_avtab_use;     /*已使用的哈希表项的数目*/
	int te_policy_num;	  /*已加载TE策略条数*/

	struct wl_avtab *wl_avtab;
	int wl_avtab_size;
	int wl_avtab_use;
	int wl_policy_num;

	struct sub_dom_map *sub_dom_map;
	int sub_dom_map_size;
	int sub_dom_map_use;
	int sdmap_policy_num;

	struct obj_type_map *obj_type_map;
	int obj_type_map_size;
	int obj_type_map_use;
	int otmap_policy_num;
	

};



struct te_avtab{
	struct te_node **te_node;
};
struct te_node{
	struct te_avtab_key *key;
	struct te_atab_datum *datum;
	struct te_node *next;
};
struct te_avtab_key{
	uint32_t source_type;
	uint32_t target_type;
	uint32_t target_class
};
struct te_avtab_datum{
	uint32_t permission;
};
struct te_node *insert_te_node(uint32_t source_type,uint32_t target_type,uint32_t target_class,uint32_t permission){
	struct te_node *te_node = (struct te_node*)vmalloc(sizeof(struct te_node));
	struct te_avtab_key *te_avtab_key = (struct te_avtab_key*)vmalloc(sizeof(struct te_avtab_key));
	te_avtab_key->source_type = source_type;
	te_avtab_key->target_type = target_type;
	te_avtab_key->target_class = target_class;
	te_node->key = te_avtab_key;
	printk("create te_node half \n");
	struct te_avtab_datum *te_avtab_datum = (struct te_avtab_datum*)vmalloc(sizeof(struct te_avtab_datum));
	te_avtab_datum->permission = permission;
	te_node->datum = te_avtab_datum;
	te_node->next = NULL;
	return te_node;
}
void free_te_node_list(struct te_node *te_node){
	if(te_node->next != NULL){
		free_te_node_list(te_node->next);
	}
	vfree(te_node->key);
	vfree(te_node->datum);
	vfree(te_node);
}



struct sub_dom_map{
	struct sdmap_node **sdmap_node;
};
struct sdmap_node {
	struct sdmap_key *key;
	struct sdmap_datum *datum;
	struct sdmap_node *next;
};
struct sdmap_key{
	char *sub_name;
};
struct sdmap_datum{
	uint32_t sub_domain;
};
struct sdmap_node *insert_sdmap_node(char *sub_name,uint32_t sub_domain){
	struct sdmap_node *sdmap_node = (struct sdmap_node*)vmalloc(sizeof(struct sdmap_node));
	char* sub_name_use = (char *)vmalloc(strlen(sub_name)*sizeof(char));
	strcpy(sub_name_use,sub_name);
	struct sdmap_key *sdmap_key = (struct sdmap_key*)vmalloc(sizeof(struct sdmap_key));
	sdmap_key->sub_name = sub_name_use;
	sdmap_node->key = sdmap_key;
	struct sdmap_datum *sdmap_datum = (struct sdmap_datum*)vmalloc(sizeof(struct sdmap_datum));
	sdmap_datum->sub_domain = sub_domain;
	sdmap_node->datum = sdmap_datum;
	sdmap_node->next = NULL;
	return sdmap_node;
}
void free_sdmap_node_list(struct sdmap_node *sdmap_node){
	if(sdmap_node->next != NULL){
		free_sdmap_node_list(sdmap_node->next);
	}
	vfree(sdmap_node->key->sub_name);
	vfree(sdmap_node->key);
	vfree(sdmap_node->datum);
	vfree(sdmap_node);
}



struct obj_type_map{
	struct objtype_node **objtype_node;
};
struct objtype_node{
	struct objtype_key *key;
	struct objtype_datum *datum;
	struct objtype_node *next;
};
struct objtype_key{
	char *obj_name;
};
struct objtype_datum{
	uint32_t obj_type;
};
/* void initial_obj_type_map(struct obj_type_map *obj_type_map){
	for(int i= 0;i<HASH_MAX_LENGTH;++i){
		objtype_node[i] = NULL;
	}
} */
struct objtype_node *insert_objtype_node(char *obj_name,uint32_t obj_type){
	struct objtype_node *objtype_node = (struct objtype_node*)vmalloc(sizeof(struct objtype_node));
	char* obj_name_use = (char *)vmalloc(strlen(obj_name)*sizeof(char));
	strcpy(obj_name_use,obj_name);
	struct objtype_key *objtype_key = (struct objtype_key*)vmalloc(sizeof(struct objtype_key));
	objtype_key->obj_name = obj_name_use;
	objtype_node->key = objtype_key;
	struct objtype_datum *objtype_datum = (struct objtype_datum*)vmalloc(sizeof(struct objtype_datum));
	objtype_datum->obj_type = obj_type;
	objtype_node->datum = objtype_datum;
	objtype_node->next = NULL;
	return objtype_node;
}
void free_objtype_node_list(struct objtype_node *objtype_node){
	if(objtype_node->next != NULL){
		free_objtype_node_list(objtype_node->next);
	}
	vfree(objtype_node->key->obj_name);
	vfree(objtype_node->key);
	vfree(objtype_node->datum);
	vfree(objtype_node);
}



struct wl_avtab_node {		/*白名单策略结点以及以下的两种映射结点，结构同TE策略结点类似，结构体各项含义可从变量的名字推断，故不赘述*/
	struct wl_avtab_key *key;
	struct wl_avtab_datum *datum;
	struct wl_avtab_node *next;
};
struct wl_avtab_key {
	char *source_name;
	char *target_name;
	uint32_t target_class;
};
struct wl_avtab_datum {
	uint32_t permission;
};
struct wl_avtab{
	struct wl_avtab_node **wl_avtab_node;
};
/* void initial_wl_avtab(struct *wl_avtab){
	for(int i= 0;i<HASH_MAX_LENGTH;++i){
		wl_avtab_node[i] = NULL;
	}
} */
struct wl_avtab_node* insert_wl_avtab_node(char *source_name,char *target_name,uint32_t target_class,uint32_t permission){
	printk("start insert_wl_avtab_node\n");
	struct wl_avtab_node *wl_avtab_node = (struct wl_avtab_node*)vmalloc(sizeof(struct wl_avtab_node));
	char *source_name_used = (char *)vmalloc(strlen(source_name)*sizeof(char));
	strcpy(source_name_used,source_name);
	struct wl_avtab_key *wl_avtab_key = (struct wl_avtab_key*)vmalloc(sizeof(struct wl_avtab_key));
	wl_avtab_key->source_name = source_name_used;
	//wl_avtab_node->key->source_name = source_name_used;
	char *target_name_used = (char *)vmalloc(strlen(target_name)*sizeof(char));
	strcpy(target_name_used,target_name);
	wl_avtab_key->target_name = target_name_used;
	wl_avtab_key->target_class = target_class;
	wl_avtab_node->key = wl_avtab_key;
	struct wl_avtab_datum *wl_avtab_datum = (struct wl_avtab_datum*)vmalloc(sizeof(struct wl_avtab_datum));	
	wl_avtab_datum->permission = permission;
	wl_avtab_node->datum = wl_avtab_datum;
	printk("alloc mem and strcpy success\n");
	wl_avtab_node->next = NULL;
	printk("wl_avtab_node= %s, %s, %d, %d\n",wl_avtab_node->key->source_name,wl_avtab_node->key->target_name,wl_avtab_node->key->target_class,wl_avtab_node->datum->permission);
	return wl_avtab_node;
}
void free_wl_avtab_node_list(struct wl_avtab_node *wl_avtab_node){
	if(wl_avtab_node->next != NULL){
		free_wl_avtab_node_list(wl_avtab_node->next);
	}
	vfree(wl_avtab_node->key->source_name);
	vfree(wl_avtab_node->key->target_name);
	vfree(wl_avtab_node->key);
	vfree(wl_avtab_node->datum);
	vfree(wl_avtab_node);
}



	void addNewTe_node(struct te_node *te_node,struct policydb *policydb){
		//calculate hash
		printk("add new te_node\n");
		int origin = te_node->key->source_type + te_node->key->target_type + te_node->key->target_class ;
		int answer = origin%policydb->te_avtab_size;
		//insert
		if(policydb->te_avtab->te_node[answer] == NULL){
			printk("insert from empty\n");
			policydb->te_avtab->te_node[answer] = te_node;
			policydb->te_avtab_use++; 
			policydb->te_policy_num++;
		}
		else{
			printk("insert from exist\n");
			struct te_node * find = policydb->te_avtab->te_node[answer];
			while(find->next != NULL){
				find = find->next;
			}
			find->next = te_node;
			policydb->te_policy_num++;
		}
		printk("add new te_node successful!\n");
	}
	void addNewWl_avtb_node(struct wl_avtab_node* wl_avtab_node,struct policydb *policydb){
		//calculate hash
		//printk("start to addNewWl_avtb_node\n");printk("wl_avtab_node= %s, %s, %d, %d\n",wl_avtab_node->key->source_name,wl_avtab_node->key->target_name,wl_avtab_node->key->target_class,wl_avtab_node->datum->permission);
		int origin = 0;
		
/*		int i = 0;
 		for(i =0;i<strlen(wl_avtab_node->key->source_name);++i){
			origin += wl_avtab_node->key->source_name[i];
		} */
		origin = BKDRHash(wl_avtab_node->key->source_name);
		int answer = origin%policydb->wl_avtab_size;
		printk("hash sucess!\n");
		//insert
		if(policydb->wl_avtab->wl_avtab_node[answer] == NULL){
			printk("NULL to insert!\n");
			policydb->wl_avtab->wl_avtab_node[answer] = wl_avtab_node;
			policydb->wl_avtab_use += 1;
			policydb->wl_policy_num += 1;
		}
		else{
			printk("list to insert!\n");
			struct wl_avtab_node * find = policydb->wl_avtab->wl_avtab_node[answer];
			while(find->next != NULL){
				find = find->next;
			}
			find->next = wl_avtab_node;
			policydb->wl_policy_num++; 
		}
	}
	void addNewSdmap_node(struct sdmap_node* sdmap_node,struct policydb *policydb){
		//calculate hash
		int origin = 0;
		int i = 0;
		/* for(i =0;i<strlen(sdmap_node->key->sub_name);++i){
			origin += sdmap_node->key->sub_name[i];
		} */
		origin = BKDRHash(sdmap_node->key->sub_name);
		int answer = origin%policydb->sub_dom_map_size;
		//insert
		if(policydb->sub_dom_map->sdmap_node[answer] == NULL){
			policydb->sub_dom_map->sdmap_node[answer] = sdmap_node;
			policydb->sub_dom_map_use++;
			policydb->sdmap_policy_num++;
		}
		else{
			struct sdmap_node *find = policydb->sub_dom_map->sdmap_node[answer];
			while(find->next != NULL){
				find = find->next;
			}
			find->next = sdmap_node;
			policydb->sdmap_policy_num++;
		}
	}
	void addNewObjtype_node(struct objtype_node* objtype_node,struct policydb *policydb){
		//calculate hash
		int origin = 0;
		int i = 0;
		/* for( i =0;i<strlen(objtype_node->key->obj_name);++i){
			origin += objtype_node->key->obj_name[i];
		} */
		origin = BKDRHash(objtype_node->key->obj_name);
		int answer = origin%policydb->obj_type_map_size;
		//insert
		if(policydb->obj_type_map->objtype_node[answer] == NULL){
			policydb->obj_type_map->objtype_node[answer] = objtype_node;
			policydb->obj_type_map_use++;
			policydb->otmap_policy_num++;
		}
		else{
			struct objtype_node * find = policydb->obj_type_map->objtype_node[answer];
			while(find->next != NULL){
				find = find->next;
			}
			find->next = objtype_node;
			policydb->otmap_policy_num++;
		}
	}
//安全服务器向对象管理器提供的策略查询接口
//主体-域映射表
uint32_t sub_dom_map_check(char *sub_name,struct policydb *policydb){
	if(sub_name == NULL)
		return 0;
	uint32_t ret = 0;
	int i = 0;
	/* for(i = 0;i<strlen(sub_name);++i){
		ret += sub_name[i];
	} */
	ret = BKDRHash(sub_name);
	ret = ret%policydb->sub_dom_map_size;
	struct sdmap_node* find = policydb->sub_dom_map->sdmap_node[ret];
	while(find != NULL){
		if(strcmp(sub_name,find->key->sub_name)==0)
			return find->datum->sub_domain;
		find = find->next;
	}
	return -1;
}
//客体-类型映射表
uint32_t obj_type_map_check(char *obj_name,struct policydb *policydb){
	if(obj_name == NULL)
		return 0;
	uint32_t ret = 0;
	int i = 0;
	/* for( i = 0;i<strlen(obj_name);++i){
		ret += obj_name[i];
	} */
	ret = BKDRHash(obj_name);
	ret = ret%policydb->obj_type_map_size;
	struct objtype_node * find = policydb->obj_type_map->objtype_node[ret];
	while(find != NULL){
		if(strcmp(obj_name,find->key->obj_name)==0)
			return find->datum->obj_type;
		find = find->next;
	}
	return -1;
}
//白名单查询(0允许，1禁止，-1未定义)

int wl_avtab_check(char* source_name, char* target_name, uint32_t target_class, uint32_t request,struct policydb *policydb){
	//printk("wl_avtab_check\n");
	if(source_name == NULL || target_name == NULL || strlen(source_name) == 0 || strlen(target_name) == 0 )
		return 0;
	int origin = 0;
	int i = 0;
		/* for(;i<strlen(source_name);++i){
			origin += source_name[i];
		} */
	origin = BKDRHash(source_name);
	int answer = origin%policydb->wl_avtab_size;
	//printk("answer = %d\n",answer);
	struct wl_avtab_node *find = policydb->wl_avtab->wl_avtab_node[answer];
	while(find != NULL){
		if(strcmp(source_name,find->key->source_name)==0 && strcmp(target_name,find->key->target_name)==0 && find->key->target_class == target_class){
			int policy = (find->datum);
			policy = policy&request;
			if(policy == 0)
				return 1;
			return 0;
		}
		find = find->next;
	}
	return -1;
}

//通用访问控制查询(1禁止，0允许)
int te_avtab_check (int source_type, int target_type, uint32_t target_class, uint32_t request,struct policydb *policydb){
	//printk("te_avtab_check\n");
	if(source_type == -1 || target_type == -1)
		return 0;
	int origin = source_type+target_type+target_class;
	int answer = origin%policydb->te_policy_num;
	printk("te_avtab_check answer = %d\n",answer);
	struct te_node *find = policydb->te_avtab->te_node[answer];
	printk("check te_node\n");
	while(find != NULL){
		if(source_type == find->key->source_type && target_type == find->key->target_type && target_class == find->key->target_class){
			int policy = (find->datum);
			policy = policy&request;
			if(policy == 0)
				return 1;
			return 0;
		}
		find = find->next;
	}
	return -1;
}