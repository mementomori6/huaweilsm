
#include "security_sever.h"

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
			int policy = (find->datum->permission);
			policy = policy&request;
			if(policy == 0)
				return 1;
			return 0;
		}
		find = find->next;
	}
	return -1;
}
//检查白名单主体名
int wl_name_check(char* source_name, struct policydb *policydb){
	//printk("wl_avtab_check\n");
	if(source_name == NULL || strlen(source_name) == 0 )
		return -1;
	int origin = 0;
	int i = 0;
	origin = BKDRHash(source_name);
	int answer = origin%policydb->wl_avtab_size;
	//printk("answer = %d\n",answer);
	struct wl_avtab_node *find = policydb->wl_avtab->wl_avtab_node[answer];
	while(find != NULL){
		if(strcmp(source_name,find->key->source_name)==0){
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
	printk("%d,%d,%d",source_type,target_type,target_class);
	int origin = source_type+target_type+target_class;
	int answer = origin%policydb->te_avtab_size;
	printk("te_avtab_check answer = %d\n",answer);
	struct te_node *find = policydb->te_avtab->te_node[answer];
	//printk("check te_node\n");
	while(find != NULL){
		if(source_type == find->key->source_type && target_type == find->key->target_type && target_class == find->key->target_class){
			int policy = (find->datum->permission);
			policy = policy&request;
			if(policy == 0)
				return 1;
			return 0;
		}
		find = find->next;
	}
	return -1;
}

void del_sdmap_node(char *sub_name, int sub_domain, struct policydb *policydb)
{
	printk("in del_sdmap_node\n");
	if(sub_name == NULL || strlen(sub_name) == 0) {
		printk("sub_name is NULL or empty.\n");
		return;
	}
	int answer = BKDRHash(sub_name) % policydb->sub_dom_map_size;
	struct sdmap_node *find = policydb->sub_dom_map->sdmap_node[answer];
	struct sdmap_node *prev = policydb->sub_dom_map->sdmap_node[answer];

	while(find != NULL) {
		if(strcmp(sub_name, find->key->sub_name) == 0) {
			//del the node
			printk("find the node and del it\n");
			if(prev == find) {
				printk("del the first node\n");
				policydb->sub_dom_map->sdmap_node[answer] = find->next;
			}
			else {
				printk("del the middle node\n");
				prev->next = find->next;
			}
			vfree(find->key->sub_name);
			vfree(find->key);
			vfree(find->datum);
			vfree(find);
			return;
		}
		prev = find;
		find = find->next;
	}
}

void del_objtype_node(char *obj_name, int obj_type, struct policydb *policydb)
{
	printk("in del_objtype_node\n");
	if(obj_name == NULL || strlen(obj_name) == 0) {
		printk("obj_name is NULL or empty\n");
		return;
	} 
	int answer = BKDRHash(obj_name) % policydb->obj_type_map_size;
	struct objtype_node *find = policydb->obj_type_map->objtype_node[answer];
	struct objtype_node *prev = policydb->obj_type_map->objtype_node[answer];

	while(find != NULL) {
		if(strcmp(obj_name, find->key->obj_name) == 0) {
			//del the node
			printk("find the node and del it\n");
			if(prev == find) {
				printk("del the first node\n");
				policydb->obj_type_map->objtype_node[answer] = find->next;
			}
			else {
				printk("del the middle node\n");
				prev->next = find->next;
			}
			vfree(find->key->obj_name);
			vfree(find->key);
			vfree(find->datum);
			vfree(find);
			return;
		}
		prev = find;
		find = find->next;
	}
}

void del_wl_node(char *source_name, char *target_name, uint32_t target_class, uint32_t request, struct policydb *policydb)
{
	printk("in del_wl_node\n");
	if(source_name == NULL || target_name == NULL || strlen(source_name) == 0 || strlen(target_name) == 0) {
		printk("source_name or target_name is empty.\n");
		return;
	}
	int answer = BKDRHash(source_name) % policydb->wl_avtab_size;
	struct wl_avtab_node *find = policydb->wl_avtab->wl_avtab_node[answer];
	struct wl_avtab_node *prev = policydb->wl_avtab->wl_avtab_node[answer];

	while(find != NULL) {
		if(strcmp(source_name, find->key->source_name) == 0 && strcmp(target_name, find->key->target_name) == 0 && target_class == find->key->target_class ) {
			//del the node
			printk("find the node and del it\n");
			if(prev == find) {
				printk("del the first node\n");
				policydb->wl_avtab->wl_avtab_node[answer] = find->next;
			}
			else {
				printk("del the middle node\n");
				prev->next = find->next;
			}
			vfree(find->key->source_name);
			vfree(find->key->target_name);
			vfree(find->key);
			vfree(find->datum);
			vfree(find);
			return;
		}
		prev = find;
		find = find->next;
	}
}


void del_te_node(int source_type, int target_type, uint32_t target_class, uint32_t request, struct policydb *policydb)
{
	printk("in del_te_node\n");
	int origin = source_type + target_type + target_class;
	int answer = origin % policydb->te_avtab_size;

	struct te_node *find = policydb->te_avtab->te_node[answer];
	struct te_node *prev = policydb->te_avtab->te_node[answer];

	while(find != NULL) {
		if(source_type == find->key->source_type && target_type == find->key->target_type && target_class == find->key->target_class) {
			//del the node
			printk("find the node and del it\n");
			if(prev == find) {
				printk("del the first node\n");
				policydb->te_avtab->te_node[answer] = find->next;
			}
			else {
				printk("del the middle node\n");
				prev->next = find->next;
			}
			vfree(find->key);
			vfree(find->datum);
			vfree(find);
			return;
		}
		prev = find;
		find = find->next;
	}
}