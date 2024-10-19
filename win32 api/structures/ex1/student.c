#include <stdio.h>

typedef struct student{
    int id;
    char name[30];
    int age;
    float gpa;
} student, *pstudent;

student add_student(int age, float gpa){
    printf("-----------------------------------------\n");
    printf("        Adding a new student record:     \n");
    printf("-----------------------------------------\n");
}

student get_student(int id){
}

void get_all_student(){
}

student update_student(){
}

void delete_student(){
}

int main(){
    printf("Here is main function\n");
    return 0;
}