#include<stdio.h>

typedef struct list_test {
	int j;
	struct list_test *next;
}T_ListText, *PT_ListText;

static PT_ListText list_head = NULL;

int insert_list(PT_ListText tmp);
int main(int argc, char **argv)
{
	int i;
	PT_ListText plist_tmp, list_tmp;
	/*static T_ListText ;*/

	list_head = malloc(sizeof(struct list_test));
	for(i = 1; i <= 20; i++)
	{
		list_tmp = malloc(sizeof(struct list_test));
		list_tmp->j = i;
		insert_list(list_tmp);
	}
	plist_tmp = list_head;
	while(plist_tmp)
	{
		printf("num = %d, line = %d\n", plist_tmp->j, __LINE__);
		plist_tmp = plist_tmp->next;
	}

}

int insert_list(PT_ListText tmp)
{
	PT_ListText plist_tmp;
	int i = 0;

	if(list_head == NULL)
	{
		printf("yes is null\n");
		list_head = tmp;
		tmp->next = NULL;
	}
	else
	{
		plist_tmp = list_head;
		while(plist_tmp->next)
		{
			plist_tmp = plist_tmp->next;
		}
		plist_tmp->next = tmp;
		/*printf("tmp.num = %d\n", tmp->i);*/
		printf("list_head.num= %d\n",list_head->j);
		tmp->next = NULL;
	}

	return 0;
}
