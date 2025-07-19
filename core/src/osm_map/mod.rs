use bevy::prelude::*;

use crate::osm_map::events::ConnectToOSMEvent;

const OSM_OVERPASS_URL: &str = "https://overpass-api.de/api/interpreter";

pub struct OSMMapPlugin;

impl Plugin for OSMMapPlugin {
    fn build(&self, app: &mut App) {
        app.insert_resource(OverpassAPI {
            overpass_api: osm_overpass::api::OverpassAPI::new(OSM_OVERPASS_URL),
        });
    }
}

#[derive(Debug, Resource)]
pub struct OverpassAPI {
    pub overpass_api: osm_overpass::api::OverpassAPI,
}
