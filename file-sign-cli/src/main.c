#include <gtk/gtk.h>

int main(int argc, char *argv[]) {
    GtkWidget *window;

    // Initialize GTK
    gtk_init(&argc, &argv);

    // Create a new top-level window
    window = gtk_window_new(GTK_WINDOW_TOPLEVEL);

    // Set the window title
    gtk_window_set_title(GTK_WINDOW(window), "File-Signer GUI");

    // Set the default window size
    gtk_window_set_default_size(GTK_WINDOW(window), 400, 200);

    // Connect the "destroy" event to gtk_main_quit to exit the application
    g_signal_connect(window, "destroy", G_CALLBACK(gtk_main_quit), NULL);

    // Display the window
    gtk_widget_show_all(window);

    // Enter the GTK main loop
    gtk_main();

    return 0;
}
