CREATE TABLE AnnBiM2MInv (id INT NOT NULL, PRIMARY KEY (id));
CREATE TABLE AnnBiM2MOwnEm (BIM2MINVERSE INT, BIM2MOWNER INT);
CREATE TABLE AnnBiM2OOwn (id INT NOT NULL, BIM2OOWNER INT, PRIMARY KEY (id));
CREATE TABLE AnnBiO2MInv (id INT NOT NULL, PRIMARY KEY (id));
CREATE TABLE AnnBiO2OInv (id INT NOT NULL, PRIMARY KEY (id));
CREATE TABLE AnnBiO2OInvAO (id INT NOT NULL, PRIMARY KEY (id));
CREATE TABLE AnnBiO2OOwn (id INT NOT NULL, BIO2OOWNER INT, PRIMARY KEY (id));
CREATE TABLE AnnRootEmRL (id INT NOT NULL, BIO2OINVERSE INT, BIM2OINVERSE INT, BIO2OINVERSEASSOCOVERRIDE INT, UNIM2OINVERSE INT, UNIO2ODUMMYFA INT, UNIO2ODUMMYPA INT, PRIMARY KEY (id));
CREATE TABLE AnnUniO2O (id INT NOT NULL, PRIMARY KEY (id));
CREATE TABLE colUniO2OOwnPAEmOC (parent_id INT, UNIO2ODUMMYPA INT, valueOrderColumn INT);
CREATE TABLE listUniO2OOwnFAEmAOOC (parent_id INT, UNIO2OINVERSEASSOCOVERRIDE INT, valueOrderColumn INT);
CREATE TABLE listUniO2OOwnFAEmOC (parent_id INT, UNIO2ODUMMYFA INT, valueOrderColumn INT);
CREATE TABLE mapKeyIntValUniO2OOwnFAEmOC (parent_id INT, mykey INT NOT NULL, value INT);
CREATE TABLE mapKeyUniO2OEmValUniO2OEmOC (parent_id INT, mykey INT, value INT);
CREATE TABLE setUniO2OOwnFAEmOC (parent_id INT, UNIO2ODUMMYFA INT, valueOrderColumn INT);
CREATE INDEX I_NNBMWNM_BIM2MINVERSE ON AnnBiM2MOwnEm (BIM2MINVERSE);
CREATE INDEX I_NNBMWNM_ELEMENT ON AnnBiM2MOwnEm (BIM2MOWNER);
CREATE INDEX I_NNBM2WN_INVERSE ON AnnBiM2OOwn (BIM2OOWNER);
CREATE INDEX I_NNB2OWN_INVERSE ON AnnBiO2OOwn (BIO2OOWNER);
CREATE INDEX I_NNRTMRL_BIO2MINVERSEENTITY ON AnnRootEmRL (BIM2OINVERSE);
CREATE INDEX I_NNRTMRL_BIO2OINVERSEASSOCIATIONOVERRIDESENTITY ON AnnRootEmRL (BIO2OINVERSEASSOCOVERRIDE);
CREATE INDEX I_NNRTMRL_BIO2OINVERSEENTITY ON AnnRootEmRL (BIO2OINVERSE);
CREATE INDEX I_NNRTMRL_UNIO2MDUMMYENTITY ON AnnRootEmRL (UNIM2OINVERSE);
CREATE INDEX I_NNRTMRL_UNIO2ODUMMYENTITY_FA ON AnnRootEmRL (UNIO2ODUMMYFA);
CREATE INDEX I_NNRTMRL_UNIO2ODUMMYENTITY_PA ON AnnRootEmRL (UNIO2ODUMMYPA);
CREATE INDEX I_CLN2PMC_PARENT_ID ON colUniO2OOwnPAEmOC (parent_id);
CREATE INDEX I_CLN2PMC_UNIO2ODUMMYENTITY_PA ON colUniO2OOwnPAEmOC (UNIO2ODUMMYPA);
CREATE INDEX I_LSTNFMC_PARENT_ID ON listUniO2OOwnFAEmAOOC (parent_id);
CREATE INDEX I_LSTNFMC_UNIO2ODUMMYENTITY_FA ON listUniO2OOwnFAEmAOOC (UNIO2OINVERSEASSOCOVERRIDE);
CREATE INDEX I_LSTNFMC_PARENT_ID1 ON listUniO2OOwnFAEmOC (parent_id);
CREATE INDEX I_LSTNFMC_UNIO2ODUMMYENTITY_FA1 ON listUniO2OOwnFAEmOC (UNIO2ODUMMYFA);
CREATE INDEX I_MPKYFMC_PARENT_ID ON mapKeyIntValUniO2OOwnFAEmOC (parent_id);
CREATE INDEX I_MPKYFMC_UNIO2ODUMMYENTITY_FA ON mapKeyIntValUniO2OOwnFAEmOC (value);
CREATE INDEX I_MPKY2MC_PARENT_ID ON mapKeyUniO2OEmValUniO2OEmOC (parent_id);
CREATE INDEX I_MPKY2MC_UNIO2ODUMMYENTITY_FA ON mapKeyUniO2OEmValUniO2OEmOC (mykey);
CREATE INDEX I_MPKY2MC_UNIO2ODUMMYENTITY_FA1 ON mapKeyUniO2OEmValUniO2OEmOC (value);
CREATE INDEX I_STN2FMC_PARENT_ID ON setUniO2OOwnFAEmOC (parent_id);
CREATE INDEX I_STN2FMC_UNIO2ODUMMYENTITY_FA ON setUniO2OOwnFAEmOC (UNIO2ODUMMYFA);
CREATE TABLE XMLBiM2MInv (id INT NOT NULL, PRIMARY KEY (id));
CREATE TABLE XMLBiM2MOwnEm (BIM2MINVERSE INT, BIM2MOWNER INT);
CREATE TABLE XMLBiM2OOwn (id INT NOT NULL, BIM2OOWNER INT, PRIMARY KEY (id));
CREATE TABLE XMLBiO2MInv (id INT NOT NULL, PRIMARY KEY (id));
CREATE TABLE XMLBiO2OInv (id INT NOT NULL, PRIMARY KEY (id));
CREATE TABLE XMLBiO2OInvAO (id INT NOT NULL, PRIMARY KEY (id));
CREATE TABLE XMLBiO2OOwn (id INT NOT NULL, BIO2OOWNER INT, PRIMARY KEY (id));
CREATE TABLE XMLRootEmRL (id INT NOT NULL, BIM2OINVERSE INT, BIO2OINVERSEASSOCOVERRIDE INT, BIO2OINVERSE INT, UNIM2OINVERSE INT, UNIO2ODUMMYFA INT, UNIO2ODUMMYPA INT, PRIMARY KEY (id));
CREATE TABLE XMLUniO2O (id INT NOT NULL, PRIMARY KEY (id));
CREATE INDEX I_XMLBWNM_BIM2MINVERSE ON XMLBiM2MOwnEm (BIM2MINVERSE);
CREATE INDEX I_XMLBWNM_ELEMENT ON XMLBiM2MOwnEm (BIM2MOWNER);
CREATE INDEX I_XMLB2WN_INVERSE1 ON XMLBiM2OOwn (BIM2OOWNER);
CREATE INDEX I_XMLB2WN_INVERSE ON XMLBiO2OOwn (BIO2OOWNER);
CREATE INDEX I_XMLRMRL_BIO2MINVERSEENTITY ON XMLRootEmRL (BIM2OINVERSE);
CREATE INDEX I_XMLRMRL_BIO2OINVERSEASSOCIATIONOVERRIDESENTITY ON XMLRootEmRL (BIO2OINVERSEASSOCOVERRIDE);
CREATE INDEX I_XMLRMRL_BIO2OINVERSEENTITY ON XMLRootEmRL (BIO2OINVERSE);
CREATE INDEX I_XMLRMRL_UNIO2MDUMMYENTITY ON XMLRootEmRL (UNIM2OINVERSE);
CREATE INDEX I_XMLRMRL_UNIO2ODUMMYENTITY_FA ON XMLRootEmRL (UNIO2ODUMMYFA);
CREATE INDEX I_XMLRMRL_UNIO2ODUMMYENTITY_PA ON XMLRootEmRL (UNIO2ODUMMYPA);