Matlab files to compute sender and receiver anonymity for the paper "dPHI: An improved high-speed network-layer anonymity protocol"
===================================================================================================================================

This folder in the repository (https://github.com/AlexB030/dPHI) contains the Matlab scripts which were used to compute the sender and receiver anonymity experiments in Section 8 "Quantitative Anonymity Analysis" of the 2020 PETs paper "dPHI: An improved high-speed network-layer anonymity protocol" by Alexander Bajic and Georg T. Becker. The code was published so that other researchers can build upon it, compare their solutions or find flaws in our ideas.

Copyright notice:
=================

The files are released under the GNU GNU General Public License v3.0 copyright file found under: https://github.com/AlexB030/dPHI/blob/master/LICENSE

Hence, feel free to use them, extend them or criticize them. Should you find major errors in the computation, please do not hesitate to contact us at <Georg.becker@ruhr-uni-bochum.de> Note however, that we cannot offer support, so if you have questions regarding the code and how to get it working, we might not be able to reply (in a timely matter or at all).

In addition, if this code or data helped you in a scientific publication, we would kindly ask you to cite the code with a reference to our PETs paper:

Alexander Bajic and Georg T. Becker "dPHI: An improved high-speed network-layer anonymity protocol" Proceedings on Privacy Enhancing Technologies 2020 [Please check the issue and page numbers, as the paper is still in the publication process when we published the data]

Importing Copyright notices regarding the CAIDA data set:
=========================================================

The network layer was imported from the CAIDA files, in particular these two files;

routeviews-rv2-20140901-1200.pfx2as file belongs to Routeviews Prefix to AS mappings Dataset for IPv4 and IPv6 <https://www.caida.org/data/routing/routeviews-prefix2as.xml> ;

20140901.as-rel.txt belongs to The CAIDA AS Relationships Dataset <https://www.caida.org/data/as-relationships/>

These files were parsed into a matlab file nographFrom2014withAll.mat. if you are using this file, you are agreeing to the CAIDA copyright license found in this repository (caida-aua.pdf) and in the provided links. We asked the CAIDA project for permission to directly publish this mat file which they kindly agreed to. If you are using the data in a scientific publication, this includes that you cite the CAIDA project accordingly and notify CAIDA about your publication (which they need for reporting to their funding agencies to keep this great project active!).

Overview of the matlab scripts and how-to
=========================================

We used Matlab 2017 for the computations, but it should be upwards compatible. We use several different scripts to run the various experiments. If you just want to generate pretty figures, there are two scripts for plotting the figures, plotReceiverAnonymity and plotSenderAnonymity. We included all intermediate data files so that you can plot and work directly with the results without needing to rerun all experiments.

We have imported the CAIDA network relationship using some manual processing and and import script. Due to the manual edition, this is the only file that will not work just by clicking run and is "unsupported". Note that you do not need to import anything from an external CAIDA homepage if you want to use the 20014 or 2019 dataset. However, you do agree with the CAIDA copyright if you do so.

Due to the many different experiments, there are a lot of different files in this repository. The three tables give an overview which file does which. The Table with main-scripts are the scripts you can directly start while the helper functions contain functions called by these main scripts. We have also included a table with the important pre-computed or imported mat files that are imported in the computations. (We have not listed all intermediate results files, but they should be self-explanatory when you look up where they are used in the printing scripts)

Remarks to inconsistent naming

This is historically grown research code, and I do apologize for some sub-optimal naming and commenting :( But hey, at least there are some comments and we published the files. Some naming that might confuse you:

-   BGP and "valleyFree" essentially mean the same thing within a file or function name. In both cases it indicates that valley free routing is used. If there is a No in front it obviously means no valley free

-   "All" within a file name refers to not only considering one shortest path as valid but all shortest paths are valid for a given source destination pair.

-   "Single" within a file name is essentially the opposite of All, in this case always only one shortest path is a valid path for a given source and destination pair.

-   Source and sender, as well as destination and receiver are the same and used interchangeably



Main Scripts:
=============
| File name | Description |
|------------------------------------|---------------------------------------------|
| plotSenderAnonymity.m | Script to plot sender anonymity figures (5 a-d and other not in the PETs paper) |
| plotReceiverAnonymity.m | Script to plot receiver anonymity figures (5 f) |
| computeshortestAllAnonymitySourceWtoD.m | Computes the sender anonymity set size for PHIand dPHI for an attacker between W and D. One can choose between IP or no IP. Outputs: sourceAnonymityWtoDforstored1000IP.mat Or sourceAnonymityWtoDforstored1000NoIP.mat |
| sourceAnonymityStoMforstored1000IP | Computes the sender anonymity set size for an attacker located between s and M for the PHI and dPHI protocol. Outputs sourceAnonymityStoMforstored1000IP.mat Or 	sourceAnonymityStoMforstored1000NoIP.mat |
| computeShortestAllAnonymityHORNET | Computes the source anonymity for HORNET. Outputs sourceAnonymityHornet1000IP.mat or sourceAnonymityHornet1000NoIP.mat |
| computeSenderAnonymityLAP | Computes source anonymity for LAP (with and without VSS) Outputs sourceAnonymityVSSwithM3forstored1000IP.mat and sourceAnonymityVSSwithM3forstored1000NoIP.mat |
| computeShortestAllNoBGBSenderAnonymityStoM | Computes sender anonymity for PHI and dPHI for S to M with a shortest path routing algorithm but no valley freeness |
| computeshortestAllAnonymitySourceStoMNoShortestPath | Computes sender anonymity for PHI and dPHI for S to M without a shortest path routing policy |
| computeShortestAllValleyfreeDestinationAnonymity | Compute receiver anonymity for PHI and dPHI |
| computeShortestAllAnonymityDestinationHORNET | Compute receiver anonymity for HORNET |
| computeSourceAndDestination | Computes an upper bound on the sender-receiver anonymity set size based on the results from sender anonymity and receiver anonymity |


Helper Functions:
=================

The following Matlabscripts implement Functions used during the computation. In particular these include some functions to compute shortest paths and to generate a PHI path.

| File name | Description |
|-------|---------|
| generateShortestValleyfreePHITrace.m | Generates a PHI trace from source to destination via the helper node using a shortest path valley free routing algorithm |
| Generates a PHI trace from source to destination via the helper node using a shortest path valley free routing algorithm | This function is identical to shortestAllBGPtreeonlyDestination, the only difference is that only c to p links are valid. THis is useful if an attacker observes a c-to-p link  or P-to-p link and hence knows that all previousnodes can only be c-to-p |
| shortestBGPtreeDestination | This function is identical to shortestBGPtreeSource, the only difference is nodes in a path are not appended at the end but inserted in the front. |
| shortestAllBGPtreeDestinationIgnoreNodes | Same function as shortestAllBGPtreeDestination but in addition it has a list of nodes that are not traversed. |
| Same function as shortestAllBGPtreeDestination but in addition it has a list of nodes that are not traversed. | computes all shortest path from the destination to the sourc. The output shortestTree contains a cell-array of path instead of a single path. |
| verifyValleyfree.m | A script to check if due to the backtracking phase valley-freeness is broken (unlikely) |
| generateShortestNoBGBPHITrace | Generates a PHI trace from source to destination via the helper node. Allways the shortest valley-free path is chosen for routes between Source and helper node, choosing midway node, midway node to destination. |
| storeMindwayNodePosition | small helper script to find position of the midway node in the PHI path and store it in an array for use by the printing function. |
| readinASGraphDirected | Script to import CAIDA dataset. Note that you do not need to do this if you use the same dataset. You need some manually editing of the CAIDA files so this file is not plug and run. |
| generateSourceDestinationList | Helper script to randomly generate 1000 (or more if you want) source destination pairs and stores and PHI paths and stores it in a file so that you can run multiple experiments using the same nodes. |

Pre-computed files:
===================

 File name | Description |
|-------|---------|
| nographFrom2014withAll.mat | This file contains the used network topology imported from the 2014 CAIDA dataset (20140901) |
| savedSourceDestinationHelperNodes2014.mat | This file contains 1000 random generated PHI path from the 2014 topology that was used in the generation |
| nographFrom2019withAll.mat | The same file as the 2014 data set but with 2019 data (20190701). However, this was not used in the PETs results, only internally to experiment with. But feel free to also experiment with it |
| midwayNodePosition.mat | The midway node position in the path for the 1000 saved nodes. Generated by storeMindwayNodePosition |






