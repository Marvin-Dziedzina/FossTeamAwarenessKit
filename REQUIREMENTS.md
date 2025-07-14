# FOSSTAK REQUIREMENTS

## Stakeholders

People that need to coordinate some physical operation where it is necessary to know where your team is and to make live updates about occuring events or updates.

## General Requirements

- Completely open source
- Can be connected to a server
- The server will receive all updates
- The server will replicate all updates to all clients
- The map data will be sourced from open street map
- The clients position will be updated to the server
- The client can place markers on the map. It will be updated to the server
- The client can make photos and upload them to the map to the positon where they where made. It will be updated to the server
- The photos will be displayed with the direction that they were made to

## Main Purpose

FOSSTAK is a open source map tool to coordinate operations and let your team know what is going on.

## Scope

* The application will use OpenStreetMaps as its map provider.

* The application will provide tools for drawing Lines, Curves and several shapes on the Map.

* The application will provide [Nato Markers](https://en.wikipedia.org/wiki/NATO_Joint_Military_Symbology) to place on to the map.

* The application will provide the functionality to take or upload pictures and position them on to the map. The facing direction will be shown and saved. The pictures will have the same functionality as the base map so you can upload maps and house plans.

* The application will provide a text chat.

* The application will have two modes: the planner mode and the mission mode.

#### Planner Mode

* The planner mode wont share your position. It will only synchronise changes made to the map.

#### Mission Mode

* The mission mode will share your position and synchronise changes made to the map.
