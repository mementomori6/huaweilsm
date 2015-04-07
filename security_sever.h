/*
该文件为安全服务器设计的头文件
该文件主要定义了策略库的各个数据结构以及向对象管理器提供的策略查询接口
具体的初始化、策略加载、策略监听以及策略查询等模块正在编码中，还未完成
*/


#include <linux/kernel.h>
const int MAX_LENGTH = 512 ;

//安全策略库数据结构设计
struct policydb{
	struct te_avtab **te_avtab;
	int te_avtab_size;	  /*哈希表的大小，通常为素数*/
	int te_avtab_use;     /*已使用的哈希表项的数目*/
	int te_policy_num;	  /*已加载TE策略条数*/

	struct wl_avtab **wl_avtab;
	int wl_avtab_size;
	int wl_avtab_use;
	int wl_policy_num;

	struct sub_dom_map **sub_dom_map;
	int sub_dom_map_size;
	int sub_dom_map_use;
	int sdmap_policy_num;

	struct obj_type_map **obj_type_map;
	int obj_type_map_size;
	int obj_type_map_use;
	int otmap_policy_num;
	
	void addNewTe_node(struct te_node *te_node){
		//calculate hash
		int origin = te_node->key->source_type + te_node->key->target_type + te_node.key->target_class ;
		int answer = origin%te_avtab_size;
		//insert
		if(te_avtab->te_node[answer] == NULL){
			te_avtab->te_node[answer] = te_node;
		}
		else{
			struct te_node * find = te_avtab->te_node[answer];
			while(find->next == NULL){
				find = find->next;
			}
			find->next = te_node;
		}
	}
	void addNewWl_avtb_node(struct wl_avtab_node* wl_avtab_node){
		//calculate hash
		int origin = 0;
		for(int i =0;wl_avtab_node->source_name[i]!='\0';++i){
			origin += wl_avtab_node->source_name[i];
		}
		int answer = origin%wl_avtab_size;
		//insert
		if(wl_avtab->wl_avtab_node[answer] == NULL){
			wl_avtab->wl_avtab_node[answer] = wl_avtab_node;
		}
		else{
			struct wl_avtab_node * find = wl_avtab->wl_avtab_node[answer];
			while(find->next == NULL){
				find = find->next;
			}
			find->next = wl_avtab_node;
		}
	}
	void addNewSdmap_node(struct sdmap_node* sdmap_node){
		//calculate hash
		int origin = 0;
		for(int i =0;sdmap_node->key->sub_name[i]!='\0';++i){
			origin += sdmap_node->key->sub_name[i];
		}
		int answer = origin%sub_dom_map_size;
		//insert
		if(sub_dom_map->sdmap_node[answer] == NULL){
			sub_dom_map->sdmap_node[answer] = sdmap_node;
		}
		else{
			struct sdmap_node * find = sub_dom_map->sdmap_node[answer];
			while(find->next == NULL){
				find = find->next;
			}
			find->next = sdmap_node;
		}
	}
	void addNewObjtype_node(struct objtype_node* objtype_node){
		//calculate hash
		int origin = 0;
		for(int i =0;objtype_node.key->obj_name[i]!='\0';++i){
			origin += objtype_node.key->obj_name[i];
		}
		int answer = origin%obj_type_map_size;
		//insert
		if(obj_type_map->objtype_node[answer] == NULL){
			obj_type_map->objtype_node[answer] = &objtype_node;
		}
		else{
			struct objtype_node * find = &obj_type_map->objtype_node[answer];
			while(find->next == NULL){
				find = &find->next;
			}
			find->next = &objtype_node;
		}
	}
};

struct te_avtab{
	te_node *te_node[MAX_LENGTH];
};
struct te_node{
	struct te_avtab_key *key;
	struct te_atab_datum *datum;
	struct te_node *next;
	struct te_node(void){
		this.next = NULL;
	}
};
struct te_avtab_key{
	uint_32 source_type;
	uint_32 target_type;
	uint_32 target_class
};
struct te_avtab_datum{
	uint_32 permission;
};



struct wl_avtab_node {		/*白名单策略结点以及以下的两种映射结点，结构同TE策略结点类似，结构体各项含义可从变量的名字推断，故不赘述*/
	struct wl_avtab_key *key;
	struct wl_avtab_datum *datum;
	struct wl_avtab_node *next;
	struct wl_avtab_node(void){
		this.next = NULL;
	}
	struct wl_avtab_node(char*source_name,char*target_name,int target_type,int permission){
		this.key->source_name = source_name;
		this.key->target_name = target_name;
		this.key->target_class = target_type;
		this.datum->permission = permission;
		this.next = NULL;
	}
}
struct wl_avtab_key {
	char *source_name;
	char *target_name;
	uint_32 target_class;
};
struct wl_avtab_datum {
	uint_32 permission;
};
struct wl_avtab{
	struct wl_avtab_node *wl_avtab_node[MAX_LENGTH];
};



struct sub_dom_map{
	sdmap_node *sdmap_node[MAX_LENGTH];
};
struct sdmap_node {
	struct sdmap_key *key;
	struct sdmap_datum *datum;
	struct sdmap_node *next;
	struct sdmap_node(void){
		this.next = NULL;
	}
};
struct sdmap_key{
	char *sub_name;
};
struct sdmap_datum{
	uint_32 sub_domain;
};



struct obj_type_map{
	struct objtype_node *objtype_node[MAX_LENGTH];
};
struct objtype_node{
	struct objtype_key *key;
	struct objtype_datum *datum;
	struct objtype_node *next;
	struct objtype_node(void){
		this.next = NULL;
	}
};
struct objtype_key{
	char *obj_name;
};
struct objtype_datum{
	uint_32 obj_type;
};

//安全服务器向对象管理器提供的策略查询接口
//主体-域映射表
uint_32 sub_dom_map_check(char *sub_name);
//客体-类型映射表
uint_32 obj_type_map_check(char *obj_name);
//白名单查询
int wl_avtab_check(char* source_name, char* target_name, uint_32 target_class, uint_32 request);
//通用访问控制查询
int te_avtab_check (int source_type, int target_type, uint_32 target_class, uint_32 request);