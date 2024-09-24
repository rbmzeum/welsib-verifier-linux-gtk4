mod imp;

use std::fs::File;

use adw::prelude::*;
use adw::subclass::prelude::*;
use adw::{ActionRow, AlertDialog, ResponseAppearance};
use gio::Settings;
use glib::{clone, Object};
use gtk::{
    gio, glib, pango, Align, CheckButton, CustomFilter, Entry, FilterListModel, Label,
    ListBoxRow, NoSelection,
    template_callbacks,
};

use crate::APP_ID;

glib::wrapper! {
    pub struct Window(ObjectSubclass<imp::Window>)
        @extends adw::ApplicationWindow, gtk::ApplicationWindow, gtk::Window, gtk::Widget,
        @implements gio::ActionGroup, gio::ActionMap, gtk::Accessible, gtk::Buildable,
                    gtk::ConstraintTarget, gtk::Native, gtk::Root, gtk::ShortcutManager;
}

impl Window {
    pub fn new(app: &adw::Application) -> Self {
        // Create new window
        Object::builder().property("application", app).build()
    }

    fn setup_callbacks(&self) {
        // println!("Setup callbacks!");
    }
}