use bevy::prelude::*;

use crate::{osm::OSMPlugin, osm_map::OSMMapPlugin};

mod osm_map;

pub struct FOSSTAKCorePlugin;

impl Plugin for FOSSTAKCorePlugin {
    fn build(&self, app: &mut App) {
        app.add_plugins(OSMMapPlugin);
    }
}
