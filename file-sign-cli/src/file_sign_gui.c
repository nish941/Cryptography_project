#include <gtk/gtk.h>

// Callback functions
void on_generate(GtkWidget *widget, gpointer data) {
  GtkWidget *dialog = gtk_message_dialog_new(GTK_WINDOW(window),
                                            GTK_DIALOG_MODAL,
                                            GTK_MESSAGE_INFO,
                                            GTK_BUTTONS_OK,
                                            "Keys generated successfully!\nPrivate Key: %s\nPublic Key: %s",
                                            private_key_path,
                                            public_key_path);
gtk_dialog_run(GTK_DIALOG(dialog));
gtk_widget_destroy(dialog);
}

void on_sign(GtkWidget *widget, gpointer data) {
    GtkWidget *dialog = gtk_file_chooser_dialog_new("Select File to Sign",
                                                    GTK_WINDOW(data),
                                                    GTK_FILE_CHOOSER_ACTION_OPEN,
                                                    "_Cancel", GTK_RESPONSE_CANCEL,
                                                    "_Open", GTK_RESPONSE_ACCEPT,
                                                    NULL);
    if (gtk_dialog_run(GTK_DIALOG(dialog)) == GTK_RESPONSE_ACCEPT) {
        char *filename = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(dialog));
        // Implement your sign logic here using 'filename'
        g_free(filename);
    }
    gtk_widget_destroy(dialog);
}

void on_verify(GtkWidget *widget, gpointer data) {
    GtkWidget *dialog = gtk_file_chooser_dialog_new("Select File to Verify",
                                                    GTK_WINDOW(data),
                                                    GTK_FILE_CHOOSER_ACTION_OPEN,
                                                    "_Cancel", GTK_RESPONSE_CANCEL,
                                                    "_Open", GTK_RESPONSE_ACCEPT,
                                                    NULL);
    if (gtk_dialog_run(GTK_DIALOG(dialog)) == GTK_RESPONSE_ACCEPT) {
        char *filename = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(dialog));
        // Implement your verify logic here using 'filename'
        g_free(filename);
    }
    gtk_widget_destroy(dialog);
}

int main(int argc, char *argv[]) {
    GtkWidget *window;
    GtkWidget *vbox;
    GtkWidget *btn_generate, *btn_sign, *btn_verify;

    gtk_init(&argc, &argv);

    // Create main window
    window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(window), "File-Signer GUI");
    gtk_window_set_default_size(GTK_WINDOW(window), 400, 200);
    g_signal_connect(window, "destroy", G_CALLBACK(gtk_main_quit), NULL);

    // Create vertical box container
    vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);
    gtk_container_add(GTK_CONTAINER(window), vbox);

    // Create buttons
    btn_generate = gtk_button_new_with_label("Generate Keys");
    btn_sign     = gtk_button_new_with_label("Sign File");
    btn_verify   = gtk_button_new_with_label("Verify Signature");

    // Pack buttons into the box
    gtk_box_pack_start(GTK_BOX(vbox), btn_generate, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(vbox), btn_sign,     TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(vbox), btn_verify,   TRUE, TRUE, 0);

    // Connect signals to callbacks
    g_signal_connect(btn_generate, "clicked", G_CALLBACK(on_generate), window);
    g_signal_connect(btn_sign,     "clicked", G_CALLBACK(on_sign),     window);
    g_signal_connect(btn_verify,   "clicked", G_CALLBACK(on_verify),   window);

    // Display all widgets
    gtk_widget_show_all(window);

    gtk_main();

    return 0;
}
