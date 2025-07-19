use bevy::a11y::AccessibilityPlugin;
use bevy::audio::AudioPlugin;
use bevy::core_pipeline::CorePipelinePlugin;
use bevy::gizmos::GizmoPlugin;
use bevy::input::InputPlugin;
use bevy::log::LogPlugin;
use bevy::prelude::*;
use bevy::render::RenderPlugin;
use bevy::render::pipelined_rendering::PipelinedRenderingPlugin;
use bevy::render::settings::{RenderCreation, WgpuSettings};
use bevy::scene::ScenePlugin;
use bevy::sprite::SpritePlugin;
use bevy::state::app::StatesPlugin;
use bevy::text::TextPlugin;
use bevy::ui::UiPlugin;
use bevy::winit::{WakeUp, WinitPlugin};

#[allow(non_upper_case_globals)]
const FIXED_REFRESH_RATE_Hz: f64 = 4.0;

#[bevy_main]
fn main() {
    let mut app = App::new();

    // Bevy Plugins
    app.add_plugins((
        LogPlugin::default(),
        MinimalPlugins.set(TaskPoolPlugin {
            task_pool_options: TaskPoolOptions::with_num_threads(3),
        }),
        WindowPlugin {
            primary_window: Some(Window {
                title: "FOSSTAK".into(),
                present_mode: bevy::window::PresentMode::Fifo,
                ..Default::default()
            }),
            ..Default::default()
        },
        AssetPlugin::default(),
        TransformPlugin::default(),
        WinitPlugin::<WakeUp>::default(),
        RenderPlugin {
            render_creation: RenderCreation::Automatic(WgpuSettings {
                power_preference: bevy::render::settings::PowerPreference::LowPower,
                ..Default::default()
            }),
            ..Default::default()
        },
        ImagePlugin::default_nearest(),
        PipelinedRenderingPlugin::default(),
        CorePipelinePlugin::default(),
        SpritePlugin::default(),
        TextPlugin::default(),
        UiPlugin::default(),
        AudioPlugin::default(),
        GizmoPlugin::default(),
    ))
    .add_plugins((
        StatesPlugin::default(),
        ScenePlugin::default(),
        InputPlugin::default(),
        AccessibilityPlugin::default(),
    ));

    // Cap Fixed schedules
    app.add_systems(Startup, |mut fixed: ResMut<Time<Fixed>>| {
        fixed.set_timestep_hz(FIXED_REFRESH_RATE_Hz);
    });

    // Custom Plugins
    app.add_plugins(core::FOSSTAKCorePlugin);

    app.run();
}
