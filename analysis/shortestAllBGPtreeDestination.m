% Authors: Georg T. Becker and Alexander Bajic
% This code was published as part of the PETs 2020 publication 
%"dPHI: An improved high-speed network-layer anonymity protocol"
% The complete code, copyright and readme can be found at https://github.com/AlexB030/dPHI
% For questions, contact georg.becker@ ruhr-uni-bochum.de

function [shortestTree treeDistances] = shortestAllBGPtreeDestination(listOfNodes,sourceCellC,sourceCellP,sourceCellPtoP,destination)
%
% This function is identical to shortestBGPtreeSource, the only difference
% is nodes in a path are not appended at the end but inserted in the front.
%this not only generates the shortest valley-free path between the
%destinations and all possible source, but computes all shortest path from
%the destination to the sourc. shortestTree therefore contains a cell-array
%of path instead of a single path.

%load('nographFrom2014withAll.mat','listOfNodes','sourceCellC','sourceCellP','sourceCellPtoP','sourceListPtoC','destinationListPtoC','sourceListPtoP','destinationListPtoP')

% % % Used for debugging onliy
% % 
% % source=randi(numOfNodes);
% % destination=randi(numOfNodes);
% % helperNode=randi(numOfNodes);
% % source=37247;
% % destination=15427;
% % helperNode=10534;

nodesToVisitC=[];
nodesToVisitP=[];
nodesToVisitPP=[];
nextNodesToVisitC=[];
nextNodesToVisitP=[];
nextNodesToVisitPP=[];
numOfNodes=size(listOfNodes,1);
treeCtoP=cell(numOfNodes,1);
treePtoC=cell(numOfNodes,1);
distancesCtoP=ones(numOfNodes,1)*inf;
distancesPtoC=ones(numOfNodes,1)*inf;

%we start at the destination node.
nodesToVisitC(1)=destination;
counterToVisitC=1;
nextCounterToVisitC=0;
counterToVisitP=0;
nextCounterToVisitP=0;

treeCtoP{destination}=[destination];
pathlength=1;
while(counterToVisitC>0 || counterToVisitP>0)
    %We first traverse from the client nodes, then peer-peer nodes than
    %peer and add new nodes that can be reached
    pathlength=pathlength+1;
    for(currNodePointer=1:counterToVisitC)
        currPathes=treeCtoP{nodesToVisitC(currNodePointer)};
        nextPathesArray=ones(size(currPathes,1),size(currPathes,2)+1);
        nextPathesArray(:,2:size(currPathes,2)+1)=currPathes;
        
        %Find all destination to source links for node nodesToVisitC(currNodePointer)
        nodesToCheckC=sourceCellC{nodesToVisitC(currNodePointer)};
        nodesToCheckP=sourceCellP{nodesToVisitC(currNodePointer)};

        % now also add possible peer edges, note that after a peer edge
        % no second peer to peer edge is allowed so we can treat is as
        % if it would have been a peer to customer edge
        nodesToCheckP=[nodesToCheckP; sourceCellPtoP{nodesToVisitC(currNodePointer)}];

        %We start by checking all client to peer links and add them if they
        %are shorter or equal to the path length
        for(i=1:size(nodesToCheckC,1))
            if(distancesCtoP(nodesToCheckC(i))==pathlength) %There was already a shortest path to this node. We have to add the current path as well
                entryToAdd=nextPathesArray;
                entryToAdd(:,1)=nodesToCheckC(i);
                treeCtoP{nodesToCheckC(i)}=[treeCtoP{nodesToCheckC(i)};entryToAdd];
            else
                if(distancesCtoP(nodesToCheckC(i))>pathlength) %We found a newest shortest path (happens if it was infinity before, hence we found the first path)
                    % this node was not found in this round yet so we need to add it to the list of nodes to visit in the next round
                        nextCounterToVisitC=nextCounterToVisitC+1;
                        nextNodesToVisitC(nextCounterToVisitC)=nodesToCheckC(i);
                        distancesCtoP(nodesToCheckC(i))=pathlength;
                        treeCtoP{nodesToCheckC(i)}=[];
                        entryToAdd=nextPathesArray;
                        entryToAdd(:,1)=nodesToCheckC(i);
                        treeCtoP{nodesToCheckC(i)}=[treeCtoP{nodesToCheckC(i)};entryToAdd];
                end
            end
        end           

 %             %We now add all new Peer-To-Customer Links but store them in the
 %             %peer array (custmer to peer are forbidden for them
          for(i=1:size(nodesToCheckP,1))
              if(distancesPtoC(nodesToCheckP(i))>pathlength)
                  nextCounterToVisitP=nextCounterToVisitP+1;
                  nextNodesToVisitP(nextCounterToVisitP)=nodesToCheckP(i);
                  distancesPtoC(nodesToCheckP(i))=pathlength;    
                  treePtoC{nodesToCheckP(i)}=[];
                  entryToAdd=nextPathesArray;
                  entryToAdd(:,1)=nodesToCheckP(i);
                  treePtoC{nodesToCheckP(i)}=[treePtoC{nodesToCheckP(i)};entryToAdd];        
              else
                  if(distancesPtoC(nodesToCheckP(i))==pathlength) %There was already a shortest path to this node. We have to add the current path as well              
                    entryToAdd=nextPathesArray;
                    entryToAdd(:,1)=nodesToCheckP(i);
                    treePtoC{nodesToCheckP(i)}=[treePtoC{nodesToCheckP(i)};entryToAdd];
                 
                  end
              end
          end   
      end

%         % Done with all nodes that were reached via Client to Peer and peer to peer. Now we
%         % check Peer to client but for those client to peer and peer to peer links are invalid.
      for(currNodePointer=1:size(nodesToVisitP,2))
        currPathes=treePtoC{nodesToVisitP(currNodePointer)};
        nextPathesArray=ones(size(currPathes,1),size(currPathes,2)+1);
        nextPathesArray(:,2:size(currPathes,2)+1)=currPathes;

       %Go through all nodes that can be reached from teh current via PtoC links
        nodesToCheckP=sourceCellP{nodesToVisitP(currNodePointer)};
        for(i=1:size(nodesToCheckP,1))
             if(distancesPtoC(nodesToCheckP(i))>pathlength)
                nextCounterToVisitP=nextCounterToVisitP+1;
                nextNodesToVisitP(nextCounterToVisitP)=nodesToCheckP(i);
                distancesPtoC(nodesToCheckP(i))=pathlength;

                treePtoC{nodesToCheckP(i)}=[];
                entryToAdd=nextPathesArray;
                entryToAdd(:,1)=nodesToCheckP(i);
                treePtoC{nodesToCheckP(i)}=[treePtoC{nodesToCheckP(i)};entryToAdd];
             else
                if(distancesPtoC(nodesToCheckP(i))==pathlength) %There was already a shortest path to this node. We have to add the current path as well                   
                    entryToAdd=nextPathesArray;
                    entryToAdd(:,1)=nodesToCheckP(i);
                    treePtoC{nodesToCheckP(i)}=[treePtoC{nodesToCheckP(i)};entryToAdd];
                end
             end
         end 
     end
      % we are done for this depth. Now we move to the next depth.
    nodesToVisitC=nextNodesToVisitC;
    nodesToVisitP=nextNodesToVisitP;
    counterToVisitC=nextCounterToVisitC;
    nextCounterToVisitC=0;
    counterToVisitP=nextCounterToVisitP;
    nextCounterToVisitP=0;
    nextNodesToVisitC=[];
    nextNodesToVisitP=[];
end

shortestTree=cell(numOfNodes,1);

chooseCtoP=find(distancesCtoP<distancesPtoC);
choosePtoC=find(distancesPtoC<distancesCtoP);
chooseCandP=find(distancesCtoP==distancesPtoC);

% for debugging only:
%disp(['chooseCtoP:' num2str(size(chooseCtoP,1)) ' choosePtoC:' num2str(size(choosePtoC,1)) ' chooseCandP:' num2str(size(chooseCandP,1))])

for(i=1:size(chooseCtoP,1))
    shortestTree{chooseCtoP(i)}=treeCtoP{chooseCtoP(i)};
end
for(i=1:size(choosePtoC,1))
    shortestTree{choosePtoC(i)}=treePtoC{choosePtoC(i)};
end


for(i=1:size(chooseCandP,1))
    %these are either path that are inff
    if(distancesPtoC(chooseCandP(i))<inf)
        shortestTree{chooseCandP(i)}=treePtoC{chooseCandP(i)};
        shortestTree{chooseCandP(i)}=[shortestTree{chooseCandP(i)}; treeCtoP{chooseCandP(i)}];
    end
end

treeDistances(choosePtoC)=distancesPtoC(choosePtoC);
treeDistances(chooseCtoP)=distancesCtoP(chooseCtoP);
treeDistances(chooseCandP)=distancesCtoP(chooseCandP);

end
