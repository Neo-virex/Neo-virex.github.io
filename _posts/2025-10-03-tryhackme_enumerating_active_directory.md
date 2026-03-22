---
title: "TryHackMe: Enumerating Active Directory"
author: NeoVirex
categories: [TryHackMe]
tags: [thm, AD, enumeration]
render_with_liquid: false
media_subpath: /images/tryhackme/tryhackme_enumerating_active_directory/
image:
  path: room_img.png
description: "A TryHackMe Active Directory enumeration write-up covering lab connectivity, credentialed access, and PowerShell-based domain recon."
---

## Connecting

![Screenshot From 2025-10-03 23-12-14.png](Screenshot_From_2025-10-03_23-12-14.png)

### checking

```jsx
──(neo㉿neo)-[~]
└─$ nmcli connection show          
NAME                UUID                                  TYPE      DEVICE 
@Abe                bd8579a0-5155-498b-9700-63dfc74a5396  wifi      wlan0  
enumad              5d0c29e3-a2a7-4a6d-b052-518e48006dc5  tun       enumad 
lo                  4a2bad37-17b1-44a2-9802-26c54f25f398  loopback  lo     
Wired connection 1  0bb3c6be-e565-3aa1-923c-78364c1f8b89  ethernet  --                                                                                
┌──(neo㉿neo)-[~] 
└─$ ip route
default via 192.168.1.1 dev wlan0 proto dhcp src 192.168.1.12 metric 600 
10.50.12.0/24 dev enumad proto kernel scope link src 10.50.12.171 
10.200.14.0/24 via 10.50.12.1 dev enumad metric 1000 
192.168.1.0/24 dev wlan0 proto kernel scope link src 192.168.1.12 metric 600                                                                        
┌──(neo㉿neo)-[~]
└─$ nslookup thmdc.za.tryhackme.com         
Server:		10.200.14.101
Address:	10.200.14.101#53

Name:	thmdc.za.tryhackme.com
Address: 10.200.14.101

   
```

```jsx
THMDC 10.200.14.101
THMIIS 10.200.14.201
THMMDT 10.200.14.202
THMJMP1 10.200.14.248
```

## the credentials

```jsx
DC: thmdc.za.tryhackme.com
IP: 10.200.14.101
Username: david.cook 
Password: P8R06ELn7kbC
```

![Screenshot From 2025-10-03 11-41-08.png](Screenshot_From_2025-10-03_11-41-08.png)

## ssh login

```jsx
$ ssh za.tryhackme.com\\david.cook@thmjmp1.za.tryhackme.com
>>
za.tryhackme.com\david.cook@thmjmp1.za.tryhackme.com's password: 
>>>
Microsoft Windows [Version 10.0.17763.1098]
(c) 2018 Microsoft Corporation. All rights reserved.

za\david.cook@THMJMP1 C:\Users\david.cook>

```

## RDP connection

```jsx
xfreerdp3 /v:10.200.14.248:3389 /u:david.cook /d:za.tryhackme.com /p:'P8R06ELn7kbC'
```

### Runas

```jsx
runas /netonly /user:za.tryhackme.com\rachel.dunn "cmd.exe"
runas /netonly /user:za.tryhackme.com\darren.davis "cmd.exe"
```

```jsx
za\david.cook@THMJMP1 C:\Users\david.cook>net user
User accounts for \\THMJMP1
-------------------------------------------------------------------------------        
Administrator            DefaultAccount           Guest
thm                      vagrant                  WDAGUtilityAccount
The command completed successfully.
za\david.cook@THMJMP1 C:\Users\david.cook>
```

### list of username : net user

### full list

```jsx
C:\>net user /domain
The request will be processed at a domain controller for domain za.tryhackme.com.

User accounts for \\THMDC.za.tryhackme.com

-------------------------------------------------------------------------------
aaron.conway             aaron.hancock            aaron.harris
aaron.johnson            aaron.lewis              aaron.moore
aaron.patel              aaron.smith              abbie.joyce
abbie.robertson          abbie.taylor             abbie.walker
abdul.akhtar             abdul.bates              abdul.holt
abdul.jones              abdul.wall               abdul.west
abdul.wilson             abigail.cox              abigail.cox1
abigail.smith            abigail.ward             abigail.wheeler
adam.heath               adam.jones               adam.parker
adam.pugh                adam.reynolds            adam.woodward
Administrator            adrian.blake             adrian.chapman
adrian.foster            adrian.wilson            aimee.ball
aimee.dean               aimee.humphries          aimee.jones
aimee.potter             aimee.robinson           alan.brown
alan.jones               albert.elliott           albert.harrison
albert.hayes             albert.hunter            albert.lee
albert.stone             alex.burrows             alex.graham
alex.harris              alexander.hale           alexander.hill
alexander.sutton         alexandra.elliott        alexandra.harrison
alexandra.howard         alexandra.richards       alexandra.saunders
alexandra.webster        alexandra.williams       alexandra.wood
alice.anderson           alice.hughes             alice.king
alice.morton             alice.pickering          alice.robinson
alison.coles             alison.hall              alison.hammond
alison.khan              alison.skinner           allan.brown
allan.dodd               allan.evans              allan.johnson
allan.kaur               allan.webb               allan.wilkinson
amanda.barnes            amanda.elliott           amanda.hammond
amanda.jackson           amanda.johnson           amanda.macdonald
amanda.parkes            amanda.slater            amanda.taylor
amber.davey              amber.lynch              amber.miller
amber.tyler              amelia.cooper            amelia.fox
amelia.horton            amelia.williams          amy.carr
amy.phillips             andrea.brookes           andrea.evans
andrea.king              andrea.kirk              andrea.lee
andrea.mitchell          andrea.shaw              andrea.smith
andrew.parkes            andrew.poole             andrew.thomas
angela.griffin           angela.rowe              angela.williams
ann.bell                 ann.clarke               ann.gardner
ann.gibbs                ann.oliver               anna.carter
anna.edwards             anna.gregory             anna.howe
anna.watts               anne.ahmed               anne.begum
anne.pearson             anne.turner              anne.wood
annette.barnett          annette.burton           annette.davies
annette.gibbs            annette.hooper           annette.manning
annette.martin           annette.smith            anthony.hill
anthony.hughes           anthony.johnson          anthony.price
anthony.reynolds         anthony.white            antony.griffin
antony.humphries         antony.robinson          antony.smith
arthur.begum             arthur.campbell          arthur.grant
arthur.hawkins           arthur.hunt              arthur.norris
arthur.tyler             ashleigh.clark           ashleigh.fowler
ashleigh.robinson        ashleigh.thompson        ashley.barker
ashley.bird              ashley.howells           ashley.stewart
ashley.warren            barbara.parker           barbara.taylor
barbara.taylor1          barbara.willis           barbara.wilson
barbara.wood             barry.brown              barry.jackson
barry.lewis              barry.mistry             barry.parsons
ben.archer               ben.baldwin              ben.clarke
ben.davies               ben.hall                 ben.hamilton
ben.james                ben.ryan                 benjamin.armstrong
benjamin.barnett         benjamin.burns           benjamin.mistry
benjamin.reid            benjamin.walker          bernard.gray
bernard.howe             bernard.miles            beth.barnes
beth.conway              beth.hart                beth.nolan
bethan.evans             bethan.fletcher          bethan.hamilton
bethan.nixon             bethany.morgan           beverley.burton
beverley.burton1         beverley.hopkins         beverley.lees
billy.armstrong          billy.davies             billy.marsh
bradley.booth            bradley.cook             bradley.evans
bradley.french           bradley.robinson         bradley.waters
brandon.brown            brandon.swift            brenda.ali
brenda.ali1              brenda.king              brenda.lloyd
brenda.parker            brett.butler             brian.griffiths
brian.morrison           brian.watts              brian.white
brian.wilson             bruce.baldwin            bruce.bowen
bruce.brown              bruce.clark              bruce.green
bruce.lloyd              bruce.mason              bruce.roberts
bruce.roberts1           bruce.robertson          bruce.robertson1
bruce.robson             bryan.chapman            bryan.hodgson
callum.bennett           callum.campbell          callum.edwards
callum.hughes            callum.jenkins           callum.steele
cameron.bailey           cameron.clarke           cameron.whitehouse
carl.cole                carl.howard              carl.hussain
carl.kaur                carl.summers             carl.thomas
carl.wilson              carly.berry              carly.edwards
carly.miles              carol.clarke             carol.cooper
carol.field              carol.holden             carol.kelly
carol.wilkinson          carol.young              carole.barry
carole.bates             carole.fisher            carole.long
carole.mason             carole.reed              caroline.baldwin
caroline.scott           carolyn.barnes           carolyn.cross
carolyn.johnson          carolyn.robson           carolyn.thomas
catherine.smith          catherine.stephens       catherine.whitehouse
charlene.barnes          charlene.cook            charlene.holland
charlene.rowe            charlene.wilson          charles.anderson
charles.ellis            charles.hall             charles.reynolds
charles.taylor           charles.wilkins          charlie.bennett
charlie.davies           charlie.holland          charlie.lee
charlie.marsh            charlie.porter           charlie.spencer
charlotte.barrett        charlotte.coleman        charlotte.parker
charlotte.ward           charlotte.wilson         chelsea.jones
chelsea.thornton         cheryl.howard            cheryl.jones
cheryl.skinner           cheryl.woods             chloe.bradshaw
chloe.carter             chloe.green              chloe.jackson
chloe.lee                chloe.patel              chloe.reid
chloe.stevens            christian.atkins         christian.bird
christian.clayton        christian.day            christian.goodwin
christian.harris         christian.kerr           christian.macdonald
christine.burton         christine.cartwright     christine.connor
christine.matthews       christine.oliver         christine.parker
christine.wall           christine.williams       christopher.king
christopher.turnbull     claire.newton            claire.west
clare.ali                clare.howard             clare.johnson
clare.jones              clare.mahmood            clare.parker
clare.pritchard          clifford.blake           clifford.davies
clifford.evans           clifford.james           clifford.jones
clifford.morrison        clifford.payne           clifford.walker
clive.griffiths          clive.lewis              clive.woods
colin.campbell           colin.murray             colin.owen
colin.price              colin.rogers             colin.scott
colin.taylor             connor.baldwin           connor.bennett
connor.collins           connor.ellis             connor.hart
connor.jones             connor.ward              conor.fowler
conor.james              conor.lamb               conor.lyons
conor.martin             conor.newton             conor.wade
craig.harris             craig.hart               craig.herbert
craig.iqbal              craig.woodward           dale.donnelly
dale.phillips            dale.wilkins             damian.cook
damian.morris            damian.thomas            damian.watson
damian.wilson            damien.allen             damien.davies
damien.horton            damien.owen              damien.willis
damien.wood              daniel.coleman           daniel.green
daniel.roberts           daniel.storey            danielle.hutchinson
danielle.johnson         danielle.kemp            danielle.pritchard
danielle.smart           danielle.smith           danielle.watkins
danny.ellis              danny.goddard            danny.parkes
darren.davis             darren.jones             darren.jones1
darren.pearce            darren.stewart           david.bennett
david.brennan            david.cook               david.hunter
david.thompson           david.wood               dawn.barnett
dawn.fox                 dawn.gibbs               dawn.gill
dawn.hughes              dawn.jordan              dawn.morrison
dawn.turner              dean.ahmed               dean.bowen
dean.leonard             dean.parsons             dean.taylor
deborah.anderson         deborah.chadwick         deborah.dyer
deborah.jones            deborah.shaw             debra.bird
debra.elliott            debra.robinson           debra.sanders
debra.stephens           declan.clarke            declan.hill
declan.jones             declan.lewis             denis.bennett
denis.george             denis.murphy             denis.patel
denise.jackson           denise.jenkins           denise.moore
denise.taylor            dennis.burke             dennis.connolly
dennis.hudson            dennis.reeves            dennis.smith
derek.bell               derek.bell1              derek.dawson
derek.lewis              derek.richardson         derek.rose
diana.carter             diana.murray             diana.murray1
diana.nolan              diana.parker             diana.price
diane.bryan              diane.collins            diane.fletcher
diane.lane               diane.north              diane.scott
diane.webster            diane.wood               dominic.clarke
dominic.elliott          dominic.webster          dominic.williams
donald.alexander         donald.barker            donald.johnston
donald.parkes            donald.phillips          donald.scott
donna.bishop             donna.cooper             donna.fisher
donna.hudson             donna.martin             donna.morris
donna.wright             dorothy.brown            dorothy.carr
dorothy.jenkins          dorothy.mason            dorothy.robinson
dorothy.schofield        dorothy.shah             dorothy.williams
dorothy.young            douglas.bryan            douglas.davies
douglas.hardy            douglas.howell           douglas.russell
duncan.ali               duncan.cooke             duncan.davies
duncan.frost             duncan.gould             duncan.nelson
duncan.powell            duncan.sharp             duncan.skinner
dylan.clark              dylan.rahman             dylan.smith
edward.ball              edward.davey             edward.dean
edward.evans             edward.fletcher          edward.gibbs
edward.hanson            edward.harris            edward.holloway
edward.mason             eileen.davies            eileen.hall
eileen.hayward           eileen.holland           eileen.knight
eileen.lewis             eileen.thompson          eileen.wilkinson
elaine.abbott            elaine.evans             elaine.james
elaine.lawrence          eleanor.cole             eleanor.grant
eleanor.heath            eleanor.hunt             eleanor.james
eleanor.poole            elizabeth.davies         elizabeth.hill
elizabeth.jackson        elizabeth.ward           elizabeth.wood
ellie.ali                ellie.barker             ellie.jones
ellie.kirby              elliot.douglas           elliot.knight
elliott.allen            elliott.benson           elliott.king
elliott.palmer           emily.harrison           emily.hunter
emily.shepherd           emma.carey               emma.donnelly
emma.johnson             emma.lewis               emma.power
eric.brookes             eric.edwards             eric.hall
eric.harding             eric.hayward             eric.johnson
eric.khan                eric.odonnell            eric.quinn
fiona.greenwood          fiona.pope               fiona.walker
fiona.wilson             frances.chapman          frances.hunt
frances.shaw             frances.singh            frances.smith
francesca.chadwick       francesca.holland        francesca.marshall
francesca.smith          francis.burke            francis.hudson
francis.phillips         francis.power            francis.turner
frank.curtis             frank.fletcher           frank.fuller
frank.lewis              frank.lewis1             frank.moss
frank.roberts            frank.sullivan           frederick.barnes
frederick.gardiner       frederick.middleton      frederick.nicholson
gail.ahmed               gail.howe                gail.hunt
gail.marsh               gail.russell             gareth.elliott
gareth.griffiths         gareth.long              gareth.mann
gareth.pearce            gareth.smith             gareth.taylor
gareth.todd              garry.birch              garry.bishop
garry.jones              garry.ross               garry.swift
garry.wood               gary.kaur                gary.moss
gary.stanley             gary.turner              gary.wall
gavin.mills              gemma.lyons              gemma.marshall
geoffrey.evans           geoffrey.hicks           geoffrey.jones
geoffrey.perry           george.black             george.bradley
george.clark             george.dale              george.kay
george.parry             george.reynolds          george.saunders
georgia.evans            georgia.king             georgia.lee
georgia.scott            georgia.walters          georgia.willis
georgia.wong             georgina.edwards         georgina.frost
georgina.hardy           georgina.harper          georgina.holt
georgina.martin          georgina.preston         georgina.rhodes
georgina.watkins         gerald.dixon             gerald.hughes
gerald.jones             gerald.smith             gerald.watts
gerald.white             geraldine.brookes        geraldine.howard
gerard.barry             gerard.davis             gerard.hammond
gerard.harding           gerard.hardy             gerard.jennings
gerard.lane              gerard.richards          gillian.begum
gillian.donnelly         gillian.hall             gillian.robertson
gillian.robinson         gillian.rowley           gillian.wilkinson
gillian.wilson           glen.briggs              glen.doherty
glen.harding             glen.hewitt              glen.jennings
glen.obrien              glen.oneill              glen.power
glenn.dyer               glenn.hill               glenn.palmer
glenn.parker             glenn.perry              glenn.stevenson
glenn.thomas             gordon.bishop            gordon.evans
gordon.holmes            gordon.jackson           gordon.stevens
gordon.yates             grace.arnold             grace.brooks
grace.edwards            grace.robertson          graeme.clarke
graeme.jones             graeme.mccarthy          graeme.saunders
graeme.stewart           graeme.williams          graham.davies
graham.gregory           graham.reynolds          gregory.brown
gregory.dale             gregory.jenkins          gregory.jones
gregory.smith            gregory.ward             gregory.williams
Guest                    guy.field                guy.green
guy.price                guy.reynolds             hannah.archer
hannah.bell              hannah.fisher            hannah.kirby
hannah.lane              hannah.lee               harriet.long
harriet.russell          harriet.wells            harry.baxter
harry.dale               harry.dixon              harry.hutchinson
harry.power              harry.taylor             harry.woodward
hayley.ahmed             hayley.howarth           hayley.lawrence
hayley.mann              hayley.newman            hayley.potts
hayley.preston           hayley.pritchard         hayley.rhodes
hayley.robertson         hazel.barrett            hazel.clark
hazel.hartley            hazel.jones              hazel.manning
hazel.simpson            hazel.smith              heather.herbert
heather.lynch            heather.smith            helen.brooks
helen.ferguson           helen.hall               helen.jones
helen.knowles            helen.marshall           helen.walker
henry.bird               henry.black              henry.jenkins
henry.miller             henry.murphy             henry.taylor
henry.thompson           henry.ward               henry.west
hilary.hall              hilary.hammond           hilary.jones
hilary.short             hilary.walters           hollie.bruce
hollie.hughes            hollie.jenkins           hollie.johnson
hollie.johnston          hollie.norris            hollie.parker
hollie.parkes            hollie.powell            hollie.stewart
hollie.talbot            hollie.williams          holly.conway
holly.cooper             holly.howard             holly.turner
holly.williams           howard.cook              howard.edwards
howard.taylor            howard.taylor1           hugh.daniels
hugh.davis               hugh.davis1              hugh.matthews
hugh.moore               hugh.morris              hugh.perry
hugh.richards            iain.butler              iain.phillips
iain.reid                iain.rogers              iain.ross
iain.williams            ian.brown                ian.connolly
ian.green                ian.jones                ian.singh
ian.wood                 irene.cooke              irene.dunn
irene.fraser             irene.mcdonald           irene.moss
jack.dennis              jack.jones               jack.osborne
jack.patel               jack.turner              jacob.butler
jacob.cooke              jacob.daniels            jacob.jenkins
jacob.marshall           jacob.robson             jacob.stevens
jacob.watson             jacqueline.adams         jacqueline.dickinson
jacqueline.godfrey       jacqueline.miller        jacqueline.wong
jade.brady               jade.cooke               jade.cooper
jade.myers               jade.norton              jade.perkins
jade.roberts             jade.williams            jake.anderson
jake.henry               jake.lee                 jake.mitchell
jake.thornton            jake.wright              james.hopkins
james.richardson         james.rowe               jamie.clayton
jamie.davis              jamie.hammond            jamie.jones
jamie.matthews           jamie.sullivan           jamie.taylor
jane.bennett             jane.brown               jane.coles
jane.elliott             jane.may                 jane.oneill
jane.shepherd            jane.stevens             janet.burgess
janet.clark              janet.cooper             janet.hewitt
janet.powell             janet.wilson             janice.davies
janice.evans             janice.mills             janice.richardson
janice.stevens           jasmine.jones            jasmine.may
jasmine.reeves           jasmine.reynolds         jasmine.shah
jasmine.smith            jasmine.stanley          jasmine.williams
jason.douglas            jason.evans              jason.knowles
jason.noble              jason.smith              jason.stewart
jay.brown                jay.ellis                jay.field
jay.hawkins              jay.lamb                 jay.smith
jay.smith1               jayne.holden             jayne.morris
jayne.webb               jayne.williams           jean.bond
jean.cooke               jean.ford                jean.newman
jean.read                jean.williams            jeffrey.ahmed
jeffrey.bailey           jeffrey.miller           jeffrey.reed
jeffrey.williams         jemma.bates              jemma.bryant
jemma.hart               jemma.harvey             jemma.howarth
jemma.jones              jenna.field              jenna.hughes
jenna.jones              jenna.kaur               jenna.king
jenna.marsh              jenna.newman             jennifer.holden
jennifer.wood            jennifer.wright          jeremy.begum
jeremy.johnson           jeremy.leonard           jeremy.marshall
jeremy.parkinson         jeremy.patel             jeremy.white
jessica.bibi             jessica.cross            jessica.davis
jessica.nash             jessica.richards         jill.baldwin
jill.banks               jill.davies              jill.fuller
jill.goodwin             jill.lawrence            jill.murphy
jill.nicholson           jill.smith               jill.wallis
jill.wood                joan.barnes              joan.miah
joanna.allen             joanna.begum             joanna.bishop
joanna.hopkins           joanna.jones             joanna.kaur
joanna.morris            joanna.taylor            joanna.walsh
joanne.barton            joanne.clark             joanne.craig
joanne.davies            joanne.francis           jodie.chamberlain
jodie.farmer             jodie.foster             jodie.jones
jodie.lawrence           jodie.lee                jodie.mason
jodie.tucker             joe.ball                 joe.craig
joe.douglas              joe.mccarthy             joe.myers
joe.phillips             joe.shaw                 joe.townsend
joel.craig               joel.harrison            joel.harrison1
joel.jones               joel.knowles             joel.murphy
joel.pearce              joel.smith               joel.stephenson
joel.turner              joel.yates               john.barker
john.barrett             john.dixon               john.wilson
john.young               john.young1              jonathan.day
jonathan.gray            jonathan.hughes          jonathan.williams
jonathan.williams1       jonathan.wright          jordan.begum
jordan.reynolds          joseph.hill              joseph.lamb
joseph.mann              joseph.marshall          joseph.mills
joseph.reid              joseph.sanderson         joseph.sheppard
joseph.watson            josephine.adams          josephine.griffin
josephine.johnson        josephine.read           josephine.skinner
josh.browne              josh.hill                josh.ross
josh.young               joshua.anderson          joshua.hodgson
joshua.moss              joshua.white             joyce.armstrong
joyce.brown              joyce.thomas             joyce.wilson
judith.bryant            judith.gray              judith.harris
judith.pearson           judith.waters            judith.yates
julia.carr               julia.hale               julia.hayward
julian.knight            julian.morris            julian.oconnor
julian.thomson           julie.bradshaw           julie.jones
julie.jones1             julie.noble              julie.watts
june.brooks              june.jones               june.moore
justin.bailey            justin.hooper            justin.mills
justin.turner            justin.wright            justin.young
karen.baker              karen.davies             karen.evans
karen.gilbert            karen.harris             karen.shaw
karen.spencer            karl.gould               karl.jones
karl.matthews            kate.brookes             kate.carr
kate.chamberlain         kate.hayes               kate.lamb
kate.savage              kate.smith               kate.wilson
katherine.brown          katherine.chamberlai     katherine.evans
katherine.harvey         katherine.jones          katherine.smith
katherine.walker         kathleen.douglas         kathleen.franklin
kathleen.green           kathleen.jackson         kathleen.jones
kathleen.phillips        kathleen.ward            kathryn.ahmed
kathryn.dickinson        kathryn.gardner          kathryn.gibson
kathryn.griffin          kathryn.hall             kathryn.mccarthy
kathryn.moore            kathryn.reeves           kathryn.stone
kathryn.sutton           katie.evans              katie.hopkins
katie.law                katie.newman             katy.carroll
katy.smith               katy.taylor              kayleigh.harper
kayleigh.morton          kayleigh.stone           keith.archer
keith.begum              keith.chapman            keith.grant
keith.hanson             keith.jones              keith.king
keith.roberts            kelly.andrews            kelly.blake
kelly.howells            kelly.taylor             kelly.vincent
kenneth.ali              kenneth.davies           kenneth.scott
kenneth.wilkins          kerry.armstrong          kerry.begum
kerry.bennett            kerry.coates             kerry.gardiner
kerry.murray             kerry.roberts            kerry.tucker
kevin.barrett            kevin.bolton             kevin.freeman
kevin.gardner            kevin.hardy              kevin.jones
kevin.kennedy            kevin.knight             kevin.marshall
kevin.richards           kevin.sharp              kevin.wheeler
kim.brown                kim.myers                kim.patel
kim.swift                kimberley.anderson       kimberley.brown
kimberley.conway         kimberley.day            kimberley.hughes
kimberley.moore          kimberley.richards       kimberley.smith
kirsty.harris            kirsty.howard            kirsty.hunt
kirsty.smith             krbtgt                   kyle.gibson
kyle.gray                kyle.jones               kyle.lamb
kyle.norton              kyle.payne               kyle.talbot
laura.brown              laura.doherty            laura.gallagher
lauren.barnes            lauren.bishop            lauren.cole
lauren.jones             lauren.smith             lawrence.brown
lawrence.hughes          lawrence.manning         lawrence.smith
lawrence.waters          leah.clarke              leah.davis
leah.davis1              leah.gray                leah.mistry
leah.murray              leah.shaw                leanne.ellis
leanne.patterson         leanne.white             lee.barrett
lee.gardner              lee.morris               lee.nicholson
lee.todd                 leigh.godfrey            leigh.jackson
leigh.murray             leigh.williams           leon.brown
leon.carr                leon.jennings            leon.myers
leon.palmer              leon.porter              leonard.holland
leonard.morton           leonard.wright           lesley.armstrong
lesley.fleming           lesley.hart              lesley.smart
leslie.jarvis            leslie.jones             leslie.russell
leslie.white             leslie.young             lewis.clarke
lewis.elliott            lewis.foster             lewis.harvey
lewis.holloway           lewis.lloyd              lewis.pickering
lewis.savage             lewis.wallis             lewis.wright
lewis.wright1            liam.arnold              liam.evans
liam.jones               liam.lawson              liam.riley
linda.adams              linda.horton             linda.kelly
linda.smith              linda.thompson           lindsey.bell
lindsey.brown            lindsey.fletcher         lindsey.little
lindsey.miller           lindsey.quinn            lisa.gregory
lisa.jarvis              lisa.scott               lisa.wilkinson
lisa.wright              lorraine.mckenzie        louis.cole
louis.day                louis.forster            louis.gill
louis.patel              louis.smith              louise.burns
louise.chapman           louise.cole              louise.hall
louise.harrison          louise.king              louise.lord
louise.lowe              louise.talbot            lucy.brown
lucy.evans               lucy.rowe                luke.davies
luke.green               luke.heath               luke.shaw
lydia.campbell           lydia.carter             lydia.jones
lydia.ward               lynda.franklin           lynda.watson
lynn.baker               lynn.patel               lynne.chapman
lynne.davies             lynne.leonard            lynne.rhodes
lynne.stewart            lynne.stewart1           lynne.ward
malcolm.akhtar           malcolm.jones            malcolm.marsh
malcolm.osullivan        malcolm.taylor           malcolm.webster
malcolm.williams         mandy.barnes             mandy.bryan
mandy.cooper             mandy.franklin           mandy.noble
mandy.palmer             mandy.roberts            mandy.webb
marc.akhtar              marc.bennett             marc.coates
marc.freeman             marc.shah                marc.warner
marcus.garner            marcus.john              marcus.jones
marcus.lawson            marcus.riley             margaret.bryan
margaret.buckley         margaret.holmes          margaret.jackson
margaret.james           margaret.rees            margaret.rowe
maria.bowen              maria.brown              maria.clarke
maria.hewitt             maria.sheppard           marian.ahmed
marian.cox               marian.elliott           marian.knowles
marian.matthews          marian.powell            marian.wilson
marian.yates             marie.fisher             marie.goodwin
marie.lewis              marie.smart              marie.smith
marie.walker             marilyn.barnett          marilyn.blake
marilyn.gibson           marilyn.glover           marilyn.harris
marilyn.phillips         marilyn.smith            marilyn.watkins
marion.chan              marion.clark             marion.evans
marion.moore             marion.powell            mark.anderson
mark.browne              mark.foster              mark.hewitt
mark.miah                mark.morris              mark.oconnor
martin.allen             martin.stewart           martyn.atkins
martyn.briggs            martyn.ellis             martyn.goddard
martyn.potts             martyn.williams          mary.doherty
mary.hunt                mary.wilson              mary.wood
mathew.allen             mathew.chambers          mathew.collins
mathew.gardiner          mathew.jackson           matthew.edwards
matthew.hart             matthew.sharp            matthew.walker
maureen.gray             maureen.marshall         maureen.middleton
maureen.powell           maurice.bell             maurice.davies
maurice.ellis            maurice.morgan           maurice.nelson
maurice.palmer           max.curtis               max.davidson
max.wallace              megan.fry                megan.harrison
megan.lowe               megan.white              melanie.field
melanie.harrison         melanie.houghton         melanie.lane
melanie.smith            melissa.holden           melissa.lane
melissa.newton           melissa.obrien           melissa.wilson
michael.chan             michael.lee              michael.swift
michael.thomas           michael.welch            michelle.bond
michelle.evans           michelle.scott           mitchell.davis
mitchell.hanson          mitchell.hill            mitchell.lewis
mitchell.murphy          mitchell.pritchard       mitchell.storey
mohamed.clarke           mohamed.connor           mohamed.grant
mohamed.griffin          mohamed.johnson          mohamed.kerr
mohamed.peters           mohamed.wright           mohammad.atkinson
mohammad.collier         mohammad.green           mohammad.jones
mohammad.martin          mohammad.naylor          mohammad.pollard
mohammad.randall         mohammad.riley           mohammad.wood
mohammad.yates           mohammed.atkins          mohammed.edwards
mohammed.hewitt          mohammed.hill            mohammed.phillips
mohammed.ryan            mohammed.stevens         mohammed.ward
molly.davey              molly.roberts            naomi.abbott
naomi.howarth            naomi.jones              naomi.lee
naomi.scott              naomi.vincent            natalie.collins
natalie.gill             natalie.griffin          natalie.hunter
natalie.moore            natalie.stephens         natalie.williams
natalie.williams1        natasha.howells          natasha.hussain
natasha.jones            natasha.martin           natasha.scott
natasha.thomas           nathan.coles             nathan.frost
nathan.james             nathan.perry             nathan.smart
neil.davies              neil.hughes              neil.payne
nicholas.goodwin         nicola.brennan           nicola.hill
nicola.little            nicola.mason             nicola.shepherd
nicole.goodwin           nicole.little            nicole.mellor
nicole.robson            nicole.smith             nicole.taylor
nicole.white             nicole.williams          nigel.bell
nigel.bowen              nigel.connor             norman.bennett
norman.hill              norman.khan              norman.stevenson
norman.weston            oliver.hill              oliver.parker
oliver.patterson         oliver.payne             olivia.goodwin
olivia.green             olivia.hancock           olivia.jones
olivia.morgan            olivia.riley             owen.barry
owen.hancock             owen.jones               owen.miller
owen.stevens             paige.bennett            paige.curtis
paige.harris             paige.king               paige.lewis
paige.taylor             paige.taylor1            pamela.cox
pamela.davidson          pamela.davies            pamela.freeman
pamela.griffin           pamela.long              pamela.singh
patricia.birch           patrick.chan             patrick.foster
patrick.foster1          patrick.gardiner         patrick.hart
patrick.spencer          patrick.williams         patrick.wilson
paul.anderson            paul.bell                paul.carter
paul.peacock             paula.hardy              paula.robinson
pauline.baker            pauline.baxter           pauline.brown
pauline.ford             pauline.howell           pauline.jones
pauline.potter           pauline.thomas           peter.charlton
peter.clark              peter.dixon              peter.evans
peter.evans1             peter.jackson            peter.robinson
philip.anderson          philip.austin            philip.bennett
philip.clements          philip.cooke             philip.evans
philip.henderson         philip.morris            philip.smith
phillip.atkinson         phillip.bradley          phillip.cross
phillip.jones            phillip.phillips         phillip.reid
phillip.watson           phillip.williams         rachael.atkinson
rachael.black            rachael.butcher          rachael.hughes
rachael.johnston         rachel.atkinson          rachel.dunn
rachel.hall              rachel.young             raymond.burton
raymond.oliver           raymond.smith            raymond.thornton
rebecca.miller           rebecca.norman           rebecca.robson
rebecca.woodward         reece.bull               reece.hewitt
reece.mitchell           reece.taylor             rhys.bailey
rhys.butcher             rhys.cooper              rhys.jones
rhys.obrien              rhys.white               richard.allen
richard.hughes           richard.webster          richard.williams
ricky.barker             ricky.king               ricky.richardson
ricky.slater             ricky.watts              rita.baker
rita.booth               rita.coates              rita.edwards
rita.frost               rita.haynes              rita.hill
rita.kent                rita.miller              robert.lowe
robert.manning           robert.smith             robin.baker
robin.carter             robin.james              robin.johnson
robin.mitchell           robin.murray             robin.oneill
robin.roberts            robin.smith              robin.taylor
robin.thomson            roger.baxter             roger.booth
roger.cooper             roger.davies             roger.knight
roger.phillips           ronald.cartwright        ronald.fletcher
ronald.goodwin           ronald.jones             ronald.macdonald
ronald.pearce            ronald.rogers            rosemary.jones
rosemary.jones1          rosemary.kay             rosemary.price
rosemary.sykes           rosie.bryant             rosie.collins
rosie.mann               rosie.norris             rosie.sykes
ross.matthews            ross.nash                ross.payne
ross.robertson           roy.barker               roy.dennis
roy.harris               roy.perry                roy.warner
russell.ahmed            russell.bates            russell.clarke
russell.holloway         russell.jones            russell.stewart
russell.sullivan         ruth.akhtar              ryan.ryan
sally.burton             sally.cole               sally.dyer
sally.edwards            sally.jones              sally.jones1
sally.kelly              sally.marsden            sally.north
sam.green                sam.hicks                sam.lee
sam.parry                sam.wright               samantha.carr
samantha.carter          samantha.davies          samantha.reeves
samantha.stevens         samantha.thompson        samuel.bird
samuel.goodwin           samuel.harrison          samuel.harvey
samuel.mccarthy          samuel.mitchell          samuel.reid
samuel.vincent           sandra.ali               sandra.baldwin
sandra.gilbert           sandra.gordon            sandra.nolan
sandra.robson            sandra.saunders          sara.ahmed
sara.clark               sara.rowley              sara.ryan
sara.young               sarah.ali                sarah.barrett
sarah.bryan              sarah.graham             sarah.lewis
sarah.marsh              sarah.marsh1             sarah.murphy
scott.dawson             scott.francis            scott.kerr
scott.scott              scott.smith              sean.banks
sean.bennett             sean.fox                 sean.harris
sean.hayward             sean.potter              sean.scott
sean.simpson             sean.wilkinson           shane.bartlett
shane.brady              shane.hall               shane.hussain
shane.smith              shannon.arnold           shannon.lee
shannon.parkin           shannon.wright           sharon.hall
sharon.nash              sharon.sutton            shaun.carter
shaun.fletcher           shaun.little             shaun.patel
shaun.singh              sheila.connolly          sheila.gardiner
sheila.marshall          sheila.miah              sheila.parry
sheila.woods             shirley.evans            shirley.forster
shirley.jones            shirley.reid             shirley.shah
sian.adams               sian.davis               sian.ford
sian.ford1               sian.gill                simon.evans
simon.gilbert            simon.griffiths          simon.osullivan
simon.sharp              simon.smith              sophie.blackburn
sophie.davies            sophie.lynch             sophie.macdonald
sophie.mann              sophie.murray            sophie.spencer
sophie.watkins           stacey.baker             stacey.cole
stacey.farmer            stacey.harvey            stacey.lawrence
stacey.payne             stacey.roberts           stacey.roberts1
stacey.walker            stacey.walton            stanley.brown
stephanie.james          stephanie.lawson         stephanie.pollard
stephanie.yates          stephen.evans            stephen.hill
stephen.mason            stephen.smith            steven.greenwood
steven.howell            steven.reynolds          steven.slater
steven.taylor            stewart.cartwright       stewart.fletcher
stuart.ahmed             stuart.byrne             stuart.hammond
stuart.jones             stuart.patel             stuart.scott
stuart.smart             stuart.thomas            susan.ellis
susan.murray             susan.warner             suzanne.akhtar
suzanne.brown            suzanne.kelly            suzanne.lloyd
suzanne.morris           svc.service              svcAV
svcFileCopy              svcLDAP                  svcMDT
sylvia.kerr              sylvia.king              sylvia.ward
t0_tinus.green           t1_arthur.tyler          t1_gary.moss
t1_henry.miller          t1_jill.wallis           t1_joel.stephenson
t1_marian.yates          t1_rosie.bryant          t2_brian.wilson
t2_chloe.carter          t2_christian.goodwin     t2_craig.iqbal
t2_gerard.davis          t2_henry.taylor          t2_jane.oneill
t2_jeremy.leonard        t2_marian.yates          t2_natasha.scott
t2_philip.clements       t2_sophie.davies         t2_tom.bray
t2_victor.fisher         t2_zoe.watson            terence.burke
terence.davison          terence.dennis           terence.flynn
terence.harris           terence.holland          terence.kirk
terence.lewis            terence.lloyd            terence.martin
terence.stokes           terence.white            teresa.anderson
teresa.bryan             teresa.green             teresa.hall
teresa.lewis             teresa.smith             terry.cartwright
terry.hopkins            terry.jones              terry.kelly
terry.morris             terry.smith              terry.thomas
thackme                  thomas.bennett           thomas.blackburn
thomas.brown             thomas.dale              thomas.elliott
thomas.tomlinson         timothy.black            timothy.stevens
timothy.thomas           timothy.wilson           tina.barker
tina.begum               tina.clayton             tina.dawson
tina.marsh               tina.sinclair            tina.williams
toby.cole                toby.dyer                toby.page
toby.roberts             toby.thompson            toby.wong
tom.barber               tom.bray                 tom.clarke
tom.jones                tom.martin               tom.norton
tom.shaw                 tom.singh                tony.armstrong
tony.holland             tony.jones               tony.newton
tony.pickering           tracey.johnson           tracey.morris
tracey.morton            tracey.phillips          tracey.turner
tracy.conway             tracy.evans              tracy.khan
tracy.macdonald          trevor.day               trevor.james
trevor.james1            trevor.newman            trevor.shaw
trevor.smith             trevor.stevens           trevor.thompson
vagrant                  valerie.davis            valerie.hawkins
valerie.jackson          valerie.lewis            vanessa.arnold
vanessa.collins          vanessa.harris           vanessa.jones
vanessa.newman           vanessa.peacock          vanessa.shepherd
victor.adams             victor.dixon             victor.edwards
victor.fisher            victor.perkins           victor.smith
victoria.jones           victoria.roberts         victoria.russell
victoria.savage          victoria.shaw            victoria.woodward
vincent.brooks           vincent.price            vincent.wood
vincent.young            wayne.bentley            wayne.harrison
wayne.henderson          wayne.walker             wayne.whitehouse
wendy.carpenter          wendy.evans              wendy.mills
wendy.roberts            wendy.taylor             wendy.whittaker
william.bailey           william.holmes           william.little
william.miah             william.payne            william.williams
yvonne.baker             yvonne.black             yvonne.craig
yvonne.grant             yvonne.johnson           yvonne.smith
zoe.barnes               zoe.ellis                zoe.fleming
zoe.hopkins              zoe.humphreys            zoe.lane
zoe.marshall             zoe.watson
The command completed successfully.

C:\>
```

```jsx
C:\>net user /domain
The request will be processed at a domain controller for domain za.tryhackme.com.
User accounts for \\THMDC.za.tryhackme.com
-------------------------------------------------------------------------------
aaron.conway             aaron.hancock            aaron.harris
aaron.johnson            aaron.lewis              aaron.moore
aaron.patel              aaron.smith              abbie.joyce
abbie.robertson          abbie.taylor             abbie.walker
...
yvonne.grant             yvonne.johnson           yvonne.smith
zoe.barnes               zoe.ellis                zoe.fleming
zoe.hopkins              zoe.humphreys            zoe.lane
zoe.marshall             zoe.watson
The command completed successfully.
C:\>
```

### smb downloading everything init

```jsx
smbclient [//za.tryhackme.com/SYSVOL](https://za.tryhackme.com/SYSVOL) -U 'za.tryhackme\david.cook' -c 'recurse; prompt; mget *'
```

### powershell

```jsx
PS C:\Users\david.cook> Get-ADUser -Filter 'Name -like "*stevens"' -Server za.tryhackme.com | Format-Table Name,SamAccountName -A

Name             SamAccountName
----             --------------
chloe.stevens    chloe.stevens
samantha.stevens samantha.stevens
mohammed.stevens mohammed.stevens
jacob.stevens    jacob.stevens
timothy.stevens  timothy.stevens
trevor.stevens   trevor.stevens
owen.stevens     owen.stevens
jane.stevens     jane.stevens
janice.stevens   janice.stevens
gordon.stevens   gordon.stevens

PS C:\Users\david.cook>
```

```jsx
PS C:\Users\david.cook> Get-ADGroup -Identity Administrators -Server za.tryhackme.com
DistinguishedName : CN=Administrators,CN=Builtin,DC=za,DC=tryhackme,DC=com
GroupCategory     : Security
GroupScope        : DomainLocal
Name              : Administrators
ObjectClass       : group
ObjectGUID        : f4d1cbcd-4a6f-4531-8550-0394c3273c4f
SamAccountName    : Administrators
SID               : S-1-5-32-544

PS C:\Users\david.cook>
```

```jsx
PS C:\Users\david.cook> Get-ADGroupMember -Identity Administrators -Server za.tryhackme.com

distinguishedName : CN=Domain Admins,CN=Users,DC=za,DC=tryhackme,DC=com
name              : Domain Admins
objectClass       : group
objectGUID        : 8a6186e5-e20f-4f13-b1b0-067f3326f67c
SamAccountName    : Domain Admins
SID               : S-1-5-21-3330634377-1326264276-632209373-512

distinguishedName : CN=Enterprise Admins,CN=Users,DC=za,DC=tryhackme,DC=com
name              : Enterprise Admins
objectClass       : group
objectGUID        : 93846b04-25b9-4915-baca-e98cce4541c6
SamAccountName    : Enterprise Admins
SID               : S-1-5-21-3330634377-1326264276-632209373-519

distinguishedName : CN=vagrant,CN=Users,DC=za,DC=tryhackme,DC=com
name              : vagrant
objectClass       : user
objectGUID        : ed901eff-9ec0-4851-ba32-7a26a8f0858f
SamAccountName    : vagrant
SID               : S-1-5-21-3330634377-1326264276-632209373-1000

distinguishedName : CN=Administrator,CN=Users,DC=za,DC=tryhackme,DC=com
name              : Administrator
objectClass       : user
objectGUID        : b10fe384-bcce-450b-85c8-218e3c79b30f
SamAccountName    : Administrator
SID               : S-1-5-21-3330634377-1326264276-632209373-500

PS C:\Users\david.cook>
```

### Titles and Distinguished

```jsx
PS C:\Users\david.cook> Get-ADUser -Identity beth.nolan -Properties Title | Select-Object Name, Title

Name       Title
----       -----
beth.nolan Senior

PS C:\Users\david.cook> Get-ADUser -Identity annette.manning -Properties DistinguishedName | Select-Object Name, DistinguishedName

Name            DistinguishedName
----            -----------------
annette.manning CN=annette.manning,OU=Marketing,OU=People,DC=za,DC=tryhackme,DC=com

PS C:\Users\david.cook>
```

```jsx
PS C:\Users\david.cook> Get-ADGroup -Identity "Tier 2 Admins" -Properties whenCreated | Select-Object Name, whenCreated
Name          whenCreated
----          -----------
Tier 2 Admins 2/24/2022 10:04:41 PM
PS C:\Users\david.cook>
```

```jsx

PS C:\Users\david.cook> ^C
PS C:\Users\david.cook> Get-ADObject -SearchBase "CN=Deleted Objects,DC=za,DC=tryhackme,DC=com" -LDAPFilter "(isDeleted=TRUE)" -IncludeDeletedObjects | Select-Object Name, DistinguishedName
PS C:\Users\david.cook> Import-Module ActiveDirectory
PS C:\Users\david.cook>
PS C:\Users\david.cook> # count all objects with an SPN, excluding krbtgt
PS C:\Users\david.cook> $count = Get-ADObject -LDAPFilter "(servicePrincipalName=*)" -Properties samAccountName,servicePrincipalName |
>>          Where-Object { $_.samAccountName -ne 'krbtgt' } |
>>          Measure-Object | Select-Object -ExpandProperty Count
PS C:\Users\david.cook>
PS C:\Users\david.cook> $count
8
PS C:\Users\david.cook> Get-ADObject -LDAPFilter "(servicePrincipalName=*)" -Properties samAccountName,servicePrincipalName,objectClass |
>>  Where-Object { $_.samAccountName -ne 'krbtgt' } |
>>  Select-Object samAccountName,objectClass,servicePrincipalName |
>>  Sort-Object samAccountName |
>>  Tee-Object -Variable spnResults |
>>  Export-Csv spn_accounts.csv -NoTypeInformation
PS C:\Users\david.cook>
PS C:\Users\david.cook> $spnResults.Count   # prints the number
8
PS C:\Users\david.cook> Get-ADUser -Filter 'servicePrincipalName -like "*"' -Properties servicePrincipalName |
>>  Where-Object { $_.SamAccountName -ne 'krbtgt' } |
>>  Select SamAccountName,Enabled,servicePrincipalName |
>>  Measure-Object

Count    : 4
Average  :
Sum      :
Maximum  :
Minimum  :
Property :
```

<style>
.center img {display:block; margin:auto;}
.wrap pre{white-space: pre-wrap;}
</style>
