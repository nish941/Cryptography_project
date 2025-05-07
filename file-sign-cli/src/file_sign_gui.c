#include <gtk/gtk.h>
#include "lamport.h"
#include "utils.h"
#include "sha256.h"

// Global paths for key files (could be set via file chooser)
static char *private_key_path = "private.key";
static char *public_key_path = "public.key";

// Callback: Generate Keys
void on_generate(GtkWidget *widget, gpointer data) {
    (void)widget;
    lamport_keypair_t kp;
    if (lamport_keygen(&kp) != 0) {
        GtkWidget *err = gtk_message_dialog_new(GTK_WINDOW(data), GTK_DIALOG_MODAL,
            GTK_MESSAGE_ERROR, GTK_BUTTONS_OK,
            "Error: Key generation failed.");
        gtk_dialog_run(GTK_DIALOG(err)); gtk_widget_destroy(err);
        return;
    }
    // Save keys
    save_keypair(private_key_path, public_key_path, &kp);
    GtkWidget *dialog = gtk_message_dialog_new(GTK_WINDOW(data), GTK_DIALOG_MODAL,
        GTK_MESSAGE_INFO, GTK_BUTTONS_OK,
        "Keys generated and saved successfully!\nPrivate Key: %s\nPublic Key: %s",
        private_key_path, public_key_path);
    gtk_dialog_run(GTK_DIALOG(dialog));
    gtk_widget_destroy(dialog);
}

// Callback: Sign File
void on_sign(GtkWidget *widget, gpointer data) {
    (void)widget;
    GtkWidget *open = gtk_file_chooser_dialog_new("Select File to Sign",
        GTK_WINDOW(data), GTK_FILE_CHOOSER_ACTION_OPEN,
        "_Cancel", GTK_RESPONSE_CANCEL,
        "_Open", GTK_RESPONSE_ACCEPT,
        NULL);
    if (gtk_dialog_run(GTK_DIALOG(open)) == GTK_RESPONSE_ACCEPT) {
        char *infile = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(open));
        // Load private key
        lamport_keypair_t kp;
        load_private_key(private_key_path, &kp);
        // Read file
        uint8_t *buf = NULL; size_t len;
        read_file(infile, &buf, &len);
        uint8_t hash[SHA256_BLOCK_SIZE];
        sha256(buf, len, hash);
        free(buf);
        uint8_t signature[LAMPORT_N][SHA256_BLOCK_SIZE];
        lamport_sign(&kp, hash, signature);
        // Save signature
        GtkWidget *save = gtk_file_chooser_dialog_new("Save Signature",
            GTK_WINDOW(data), GTK_FILE_CHOOSER_ACTION_SAVE,
            "_Cancel", GTK_RESPONSE_CANCEL,
            "_Save", GTK_RESPONSE_ACCEPT,
            NULL);
        gtk_file_chooser_set_do_overwrite_confirmation(GTK_FILE_CHOOSER(save), TRUE);
        gtk_file_chooser_set_current_name(GTK_FILE_CHOOSER(save), "signature.sig");
        if (gtk_dialog_run(GTK_DIALOG(save)) == GTK_RESPONSE_ACCEPT) {
            char *out = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(save));
            save_signature(out, signature);
            GtkWidget *msg = gtk_message_dialog_new(GTK_WINDOW(data), GTK_DIALOG_MODAL,
                GTK_MESSAGE_INFO, GTK_BUTTONS_OK,
                "File signed successfully!\nSignature saved to: %s", out);
            gtk_dialog_run(GTK_DIALOG(msg)); gtk_widget_destroy(msg);
            g_free(out);
        }
        gtk_widget_destroy(save);
        g_free(infile);
    }
    gtk_widget_destroy(open);
}

// Callback: Verify Signature
void on_verify(GtkWidget *widget, gpointer data) {
    (void)widget;
    // Choose input file
    GtkWidget *open = gtk_file_chooser_dialog_new("Select File to Verify",
        GTK_WINDOW(data), GTK_FILE_CHOOSER_ACTION_OPEN,
        "_Cancel", GTK_RESPONSE_CANCEL,
        "_Open", GTK_RESPONSE_ACCEPT,
        NULL);
    char *infile = NULL; char *sigfile = NULL;
    if (gtk_dialog_run(GTK_DIALOG(open)) == GTK_RESPONSE_ACCEPT) {
        infile = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(open));
    }
    gtk_widget_destroy(open);
    if (!infile) return;
    // Choose signature file
    GtkWidget *open2 = gtk_file_chooser_dialog_new("Select Signature File",
        GTK_WINDOW(data), GTK_FILE_CHOOSER_ACTION_OPEN,
        "_Cancel", GTK_RESPONSE_CANCEL,
        "_Open", GTK_RESPONSE_ACCEPT,
        NULL);
    if (gtk_dialog_run(GTK_DIALOG(open2)) == GTK_RESPONSE_ACCEPT) {
        sigfile = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(open2));
    }
    gtk_widget_destroy(open2);
    if (!sigfile) { g_free(infile); return; }
    // Load public key
    lamport_keypair_t kp;
    load_public_key(public_key_path, &kp);
    // Read and hash file
    uint8_t *buf = NULL; size_t len;
    read_file(infile, &buf, &len);
    uint8_t hash[SHA256_BLOCK_SIZE]; sha256(buf, len, hash);
    free(buf);
    // Load signature
    uint8_t signature[LAMPORT_N][SHA256_BLOCK_SIZE];
    load_signature(sigfile, signature);
    // Verify
    gboolean ok = lamport_verify(&kp, hash, signature);
    GtkWidget *msg = gtk_message_dialog_new(GTK_WINDOW(data), GTK_DIALOG_MODAL,
        ok ? GTK_MESSAGE_INFO : GTK_MESSAGE_ERROR,
        GTK_BUTTONS_OK,
        ok ? "Signature is valid!" : "Signature is INVALID!");
    gtk_dialog_run(GTK_DIALOG(msg)); gtk_widget_destroy(msg);
    g_free(infile); g_free(sigfile);
}

int main(int argc, char *argv[]) {
    GtkWidget *window;
    GtkWidget *vbox;
    GtkWidget *btn_generate, *btn_sign, *btn_verify;

    gtk_init(&argc, &argv);
    window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(window), "File-Signer GUI");
    gtk_window_set_default_size(GTK_WINDOW(window), 400, 200);
    g_signal_connect(window, "destroy", G_CALLBACK(gtk_main_quit), NULL);
    vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);
    gtk_container_add(GTK_CONTAINER(window), vbox);
    btn_generate = gtk_button_new_with_label("Generate Keys");
    btn_sign     = gtk_button_new_with_label("Sign File");
    btn_verify   = gtk_button_new_with_label("Verify Signature");
    gtk_box_pack_start(GTK_BOX(vbox), btn_generate, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(vbox), btn_sign,     TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(vbox), btn_verify,   TRUE, TRUE, 0);
    g_signal_connect(btn_generate, "clicked", G_CALLBACK(on_generate), window);
    g_signal_connect(btn_sign,     "clicked", G_CALLBACK(on_sign),     window);
    g_signal_connect(btn_verify,   "clicked", G_CALLBACK(on_verify),   window);
    gtk_widget_show_all(window);
    gtk_main();
    return 0;
}
